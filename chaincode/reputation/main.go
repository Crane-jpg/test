package main

import (
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract implements the reputation logic.
type SmartContract struct {
	contractapi.Contract
}

// DeviceState keeps track of the Dirichlet vector, statistics, and policy hints.
type DeviceState struct {
	DeviceID       string             `json:"deviceId"`
	Alpha          map[string]float64 `json:"alpha"`
	LastUpdateTime time.Time          `json:"lastUpdateTime"`
	Probabilities  map[string]float64 `json:"probabilities"`
	Score          float64            `json:"score"`
	Profile        string             `json:"profile"`
	SampleRate     float64            `json:"sampleRate"`
	UrgentFlag     bool               `json:"urgentFlag"`
	History        []Evidence         `json:"history"`
}

// Evidence captures a single observation that updates the Dirichlet vector.
type Evidence struct {
	Timestamp time.Time `json:"timestamp"`
	State     string    `json:"state"`
	Weight    float64   `json:"weight"`
	Note      string    `json:"note,omitempty"`
}

var stateLabels = []string{"Good", "Benign", "Suspicious", "Malicious"}

const (
	firstPhaseMinutes  = 30
	secondPhaseMinutes = 120
	k1                 = 0.005 // linear coefficient
	k2                 = 0.02  // exponential rate
	k3                 = 0.7   // power-law exponent

	wBenign      = 15.0
	wSuspicious  = 35.0
	baseScore    = 100.0
	maliciousK   = 4.0
	malThreshold = 0.001
	susThreshold = 0.15
	benThreshold = 0.25
)

// RegisterDevice seeds a new Dirichlet vector for the given device ID.
func (s *SmartContract) RegisterDevice(ctx contractapi.TransactionContextInterface, deviceID string) error {
	if deviceID == "" {
		return fmt.Errorf("deviceID is required")
	}

	exists, err := s.DeviceExists(ctx, deviceID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("device %s already registered", deviceID)
	}

	alpha := map[string]float64{
		"Good":       1.0,
		"Benign":     1.0,
		"Suspicious": 1.0,
		"Malicious":  1.0,
	}

	device := DeviceState{
		DeviceID:       deviceID,
		Alpha:          alpha,
		LastUpdateTime: time.Now().UTC(),
		History:        []Evidence{},
	}

	s.refreshMetrics(&device)

	payload, err := json.Marshal(device)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(deviceID, payload)
}

// SubmitEvidence ingests a new observation coming from the IoT-Fabric gateway layer.
func (s *SmartContract) SubmitEvidence(ctx contractapi.TransactionContextInterface, deviceID, behaviorState string, weight float64, note string) (*DeviceState, error) {
	if weight <= 0 {
		return nil, fmt.Errorf("weight must be positive")
	}

	device, err := s.FetchDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	if !isValidState(behaviorState) {
		return nil, fmt.Errorf("invalid state %s", behaviorState)
	}

	now := time.Now().UTC()
	lambda := decayCoefficient(device.LastUpdateTime, now)

	for _, label := range stateLabels {
		device.Alpha[label] = device.Alpha[label] * lambda
	}

	device.Alpha[behaviorState] += weight
	device.LastUpdateTime = now
	device.History = append(device.History, Evidence{
		Timestamp: now,
		State:     behaviorState,
		Weight:    weight,
		Note:      note,
	})

	s.refreshMetrics(&device)

	payload, err := json.Marshal(device)
	if err != nil {
		return nil, err
	}

	if err := ctx.GetStub().PutState(deviceID, payload); err != nil {
		return nil, err
	}

	return &device, nil
}

// QueryDevice returns the state for the given ID.
func (s *SmartContract) QueryDevice(ctx contractapi.TransactionContextInterface, deviceID string) (*DeviceState, error) {
	device, err := s.FetchDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	return &device, nil
}

// QueryAllDevices returns every registered device.
func (s *SmartContract) QueryAllDevices(ctx contractapi.TransactionContextInterface) ([]DeviceState, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var devices []DeviceState
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var device DeviceState
		if err := json.Unmarshal(queryResponse.Value, &device); err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, nil
}

// DeviceExists checks whether the key is already on the ledger.
func (s *SmartContract) DeviceExists(ctx contractapi.TransactionContextInterface, deviceID string) (bool, error) {
	if deviceID == "" {
		return false, fmt.Errorf("deviceID is required")
	}

	data, err := ctx.GetStub().GetState(deviceID)
	if err != nil {
		return false, err
	}
	return data != nil, nil
}

// FetchDevice retrieves the on-ledger record.
func (s *SmartContract) FetchDevice(ctx contractapi.TransactionContextInterface, deviceID string) (DeviceState, error) {
	payload, err := ctx.GetStub().GetState(deviceID)
	if err != nil {
		return DeviceState{}, err
	}
	if payload == nil {
		return DeviceState{}, fmt.Errorf("device %s not found", deviceID)
	}

	var device DeviceState
	if err := json.Unmarshal(payload, &device); err != nil {
		return DeviceState{}, err
	}
	return device, nil
}

func decayCoefficient(last time.Time, current time.Time) float64 {
	if last.IsZero() {
		return 1
	}

	delta := current.Sub(last)
	if delta <= 0 {
		return 1
	}

	minutes := delta.Minutes()
	switch {
	case minutes <= firstPhaseMinutes:
		value := 1 - k1*minutes
		if value < 0 {
			return 0
		}
		return value
	case minutes <= secondPhaseMinutes:
		lambdaT1 := 1 - k1*firstPhaseMinutes
		return lambdaT1 * math.Exp(-k2*(minutes-firstPhaseMinutes))
	default:
		lambdaT1 := 1 - k1*firstPhaseMinutes
		lambdaT2 := lambdaT1 * math.Exp(-k2*(secondPhaseMinutes-firstPhaseMinutes))
		return lambdaT2 * math.Pow(minutes/secondPhaseMinutes, -k3)
	}
}

func (s *SmartContract) refreshMetrics(device *DeviceState) {
	total := 0.0
	for _, label := range stateLabels {
		total += device.Alpha[label]
	}
	if total == 0 {
		total = 1
	}

	if device.Probabilities == nil {
		device.Probabilities = make(map[string]float64)
	}

	for _, label := range stateLabels {
		device.Probabilities[label] = device.Alpha[label] / total
	}

	pGood := device.Probabilities["Good"]
	pBenign := device.Probabilities["Benign"]
	pSusp := device.Probabilities["Suspicious"]
	pMal := device.Probabilities["Malicious"]

	score := baseScore*pGood - (wBenign*pBenign + wSuspicious*pSusp) - baseScore*(math.Exp(maliciousK*pMal)-1)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	device.Score = score

	device.Profile = classifyProfile(pBenign, pSusp, pMal)
	device.SampleRate, device.UrgentFlag = policyHints(device.Profile)
}

func classifyProfile(pBenign, pSusp, pMal float64) string {
	switch {
	case pMal > malThreshold:
		return "Malicious"
	case pSusp > susThreshold:
		return "Suspicious"
	case pBenign > benThreshold:
		return "Unstable"
	default:
		return "Trusted"
	}
}

func policyHints(profile string) (float64, bool) {
	switch profile {
	case "Malicious":
		return 1.0, true
	case "Suspicious":
		return 1.0, false
	case "Unstable":
		return 0.5, false
	default:
		return 0.1, false
	}
}

func isValidState(state string) bool {
	for _, label := range stateLabels {
		if label == state {
			return true
		}
	}
	return false
}

func main() {
	chaincode, err := contractapi.NewChaincode(new(SmartContract))
	if err != nil {
		panic(fmt.Sprintf("Error create reputation chaincode: %s", err))
	}

	if err := chaincode.Start(); err != nil {
		panic(fmt.Sprintf("Error starting chaincode: %s", err))
	}
}
