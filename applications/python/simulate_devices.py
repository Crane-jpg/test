import json
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple

import yaml
from fabric_gateway import Gateway, Identity, create_grpc_connection, signers
from cryptography.hazmat.primitives import serialization


@dataclass
class DeviceScenario:
    device_id: str
    behavior_weights: Dict[str, float]
    note: str

    def draw_event(self) -> Tuple[str, float, str]:
        states = list(self.behavior_weights.keys())
        weights = [self.behavior_weights[s] for s in states]
        state = random.choices(states, weights=weights, k=1)[0]
        weight = 1.0 + random.random()
        return state, weight, self.note


def read_config():
    cfg_path = Path(__file__).with_name("config.yaml")
    with cfg_path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def new_signer(key_dir: Path) -> Signer:
    key_files = list(key_dir.glob("*_sk")) or list(key_dir.glob("*.pem")) or list(key_dir.glob("*"))
    if not key_files:
        raise FileNotFoundError(f"No private key found under {key_dir}")
    key_file = key_files[0]
    key_pem = key_file.read_bytes()
    private_key = serialization.load_pem_private_key(key_pem, password=None, backend=default_backend())

    def sign(digest: bytes) -> bytes:
        return private_key.sign(digest, serialization.NoEncryption())

    return Signer(private_key)


def identity_from_config(cfg: dict) -> Identity:
    credentials = Path(cfg["cert_path"]).expanduser().resolve().read_bytes()
    return Identity(msp_id=cfg["msp_id"], credentials=credentials)


def signer_from_config(cfg: dict):
    key_dir = Path(cfg["key_path"]).expanduser().resolve()
    key_files = list(key_dir.glob("*_sk")) or list(key_dir.glob("*.pem")) or list(key_dir.glob("*"))
    if not key_files:
        raise RuntimeError(f"No private key file in {key_dir}")
    private_key = serialization.load_pem_private_key(key_files[0].read_bytes(), password=None)
    return signers.create_private_key_signer(private_key)


def new_grpc_connection(cfg: dict):
    tls_cert_path = Path(cfg["tls_cert_path"]).expanduser().resolve()
    tls_cert = tls_cert_path.read_bytes()
    cert = grpc.ssl_channel_credentials(root_certificates=tls_cert)
    options = (("grpc.ssl_target_name_override", cfg["host_alias"]),)
    return create_grpc_connection(cfg["peer_endpoint"], cert, options)


def register_devices(contract, devices):
    for device in devices:
        try:
            contract.submit_transaction("RegisterDevice", device.device_id)
            print(f"[+] Registered device {device.device_id}")
        except Exception as exc:
            if "already registered" in str(exc):
                print(f"[~] Device {device.device_id} already registered")
            else:
                raise


def simulate(contract, devices, iterations=15, delay=1.0):
    for i in range(iterations):
        print(f"\n=== Iteration {i+1} ===")
        for device in devices:
            state, weight, note = device.draw_event()
            response = contract.submit_transaction("SubmitEvidence", device.device_id, state, f"{weight:.4f}", note)
            parsed = json.loads(response)
            score = parsed["score"]
            profile = parsed["profile"]
            probs = parsed["probabilities"]
            print(
                f"{device.device_id:>15} -> {state:<11} score={score:6.2f} profile={profile:<10} "
                f"P={{{Good:.2f}, Benign:.2f, Suspicious:.2f, Malicious:.4f}}".format(**probs)
            )
        time.sleep(delay)


def main():
    cfg = read_config()["gateway"]
    identity = identity_from_config(cfg)
    signer = signer_from_config(cfg)

    with new_grpc_connection(cfg) as channel:
        with Gateway(channel=channel, identity=identity, signer=signer) as gateway:
            network = gateway.get_network(cfg["channel_name"])
            contract = network.get_contract(cfg["chaincode_name"])

            devices = [
                DeviceScenario("device-good-01", {"Good": 0.9, "Benign": 0.08, "Suspicious": 0.02}, "Routine sensor reading"),
                DeviceScenario("device-flaky-02", {"Good": 0.55, "Benign": 0.4, "Suspicious": 0.05}, "Intermittent connectivity"),
                DeviceScenario("device-probe-03", {"Good": 0.2, "Benign": 0.1, "Suspicious": 0.6, "Malicious": 0.1}, "Aggressive probing"),
                DeviceScenario("device-mal-04", {"Good": 0.05, "Benign": 0.05, "Suspicious": 0.2, "Malicious": 0.7}, "Known malicious actor"),
            ]

            register_devices(contract, devices)
            simulate(contract, devices, iterations=12, delay=0.5)


if __name__ == "__main__":
    main()
