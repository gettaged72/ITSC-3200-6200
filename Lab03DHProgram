import hashlib
import secrets
import os


# --- UI HELPER FUNCTIONS ---
def print_header(text):
    print(f"\n{'='*60}\n{text}\n{'='*60}")

def print_step(text):
    print(f"\n>> {text}")

def print_info(label, value):
    print(f"   [{label}]: {str(value)[:70]}...")


# --- Define Diffie-Hellman Constants G and P ---
P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

G = 2


# --- PART A: STATEFUL PRNG ---

class SecurePRNG:
    """
    Rollback-resistant PRNG:
    - state is updated one-way every time we generate output
    - attacker who learns current state cannot derive prior states (under hash assumptions)
    """
    def __init__(self, seed_int: int):
        # Normalize seed -> bytes, then hash into fixed-size state.
        seed_bytes = str(seed_int).encode("utf-8")
        self.state = hashlib.sha256(seed_bytes).digest()

    def generate(self, n_bytes: int) -> bytes:
        output = b""
        while len(output) < n_bytes:
            # Produce block from current state
            block = hashlib.sha256(self.state).digest()
            output += block

            # Update state immediately (rollback resistance)
            self.state = hashlib.sha256(self.state).digest()

        return output[:n_bytes]


def xor_crypt(data: bytes, prng: SecurePRNG) -> bytes:
    """
    Simple XOR stream cipher: ciphertext = plaintext XOR keystream
    Decrypt is same operation since XOR is its own inverse.
    """
    keystream = prng.generate(len(data))
    return bytes(d ^ k for d, k in zip(data, keystream))


# --- PART B: COMMUNICATION PROTOCOL ---

class Entity:
    def __init__(self, name: str):
        self.name = name
        # private exponent in [1, P-2]
        self.private_key = secrets.randbelow(P - 2) + 1
        self.public_key = pow(G, self.private_key, P)
        self.session_prng = None

    def get_public_hex(self) -> str:
        return hex(self.public_key)

    def establish_session(self, partner_pub_hex: str):
        partner_pub = int(partner_pub_hex, 16)
        shared_secret = pow(partner_pub, self.private_key, P)
        self.session_prng = SecurePRNG(shared_secret)


# --- DO NOT MODIFY THIS CLASS --- #
class Network:
    def __init__(self):
        self.mallory = None  # The interceptor 'hook'

    def send(self, sender, recipient, payload):
        print(f"[NET] {sender} -> {recipient}: {str(payload)[:60]}...")
        if self.mallory:
            return self.mallory.intercept(sender, recipient, payload)
        return payload


# --- PART C: THE MALLORY MITM PROXY ---

class Mallory:
    def __init__(self):
        self.private_key = secrets.randbelow(P - 2) + 1
        self.public_key = pow(G, self.private_key, P)
        self.public_hex = hex(self.public_key)

        # Mallory maintains TWO sessions
        self.alice_prng = None
        self.bob_prng = None

    def intercept(self, sender, recipient, payload):
        # 1. Key Exchange Interception
        if isinstance(payload, str) and payload.startswith("0x"):
            remote_pub = int(payload, 16)
            my_shared_secret = pow(remote_pub, self.private_key, P)

            # If the sender is Alice, build PRNG shared with Alice.
            if sender == "Alice":
                self.alice_prng = SecurePRNG(my_shared_secret)

            # If the sender is Bob, build PRNG shared with Bob.
            elif sender == "Bob":
                self.bob_prng = SecurePRNG(my_shared_secret)

            # Return Mallory's public key instead so both endpoints establish with Mallory.
            return self.public_hex

        # 2. Message Interception/Modification
        if isinstance(payload, bytes):
            print(f"[MALLORY] Intercepting Encrypted Message from {sender}...")

            # Decrypt using session with sender, re-encrypt using session with recipient.
            if sender == "Alice":
                if self.alice_prng is None or self.bob_prng is None:
                    print("[MALLORY] Missing session keys; passing through.")
                    return payload

                plaintext = xor_crypt(payload, self.alice_prng)
                try:
                    print("[MALLORY] Decrypted plaintext:", plaintext.decode())
                except UnicodeDecodeError:
                    print("[MALLORY] Decrypted plaintext (raw bytes):", plaintext)

                # Modify the plaintext message in some way
                modified = plaintext.replace(b"9pm", b"3am")

                # Re-encrypt for Bob
                re_encrypted = xor_crypt(modified, self.bob_prng)
                return re_encrypted

            # if Bob sends messages back to Alice, handle similarly:
            if sender == "Bob":
                if self.alice_prng is None or self.bob_prng is None:
                    return payload
                plaintext = xor_crypt(payload, self.bob_prng)
                modified = plaintext  # or modify if you want
                return xor_crypt(modified, self.alice_prng)

        return payload


# --- MAIN EXECUTION SIMULATION ---
def main():
    # ==========================================
    # SCENARIO A: BENIGN (SECURE) COMMUNICATION
    # ==========================================
    print_header("SCENARIO A: BENIGN (SECURE) COMMUNICATION")

    alice = Entity("Alice")
    bob = Entity("Bob")
    net = Network()

    # Display Group Parameters
    print_step("Step 0: Global Group Parameters")
    print_info("G (Generator)", G)
    print_info("P (Prime)", P)

    print_step("Step 1: Public Key Exchange")
    print_info("Alice Private (a)", alice.private_key)
    print_info("Bob Private (b)", bob.private_key)

    # Alice -> Bob
    alice_pub = alice.get_public_hex()
    print_info("Alice Public (A = G^a mod P)", alice_pub)
    key_for_bob = net.send("Alice", "Bob", alice_pub)

    # Bob -> Alice
    bob_pub = bob.get_public_hex()
    print_info("Bob Public (B = G^b mod P)", bob_pub)
    key_for_alice = net.send("Bob", "Alice", bob_pub)

    print_step("Step 2: Establishing Sessions")
    alice.establish_session(key_for_alice)
    bob.establish_session(key_for_bob)
    print("   [Status]: Shared Secret computed: S = B^a mod P = A^b mod P")

    print_step("Step 3: Secure Message Transmission")
    message = b"Meet me at 9pm."  # Put in your test message here
    encrypted_msg = xor_crypt(message, alice.session_prng)
    delivered_data = net.send("Alice", "Bob", encrypted_msg)
    final_message = xor_crypt(delivered_data, bob.session_prng)

    print_info("Bob decrypted", final_message.decode(errors="replace"))

    # ==========================================
    # SCENARIO B: MALICIOUS (MITM) ATTACK
    # ==========================================
    print_header("SCENARIO B: MALICIOUS (MITM) ATTACK")

    alice = Entity("Alice")
    bob = Entity("Bob")
    mallory = Mallory()
    net = Network()
    net.mallory = mallory

    print_step("Step 1: Mallory's Parameters")
    print_info("Mallory Private (m)", mallory.private_key)
    print_info("Mallory Public (M)", mallory.public_hex)

    print_step("Step 2: Compromised Key Exchange")
    print("Alice sending key to Bob...")
    key_for_bob = net.send("Alice", "Bob", alice.get_public_hex())

    print("Bob sending key to Alice...")
    key_for_alice = net.send("Bob", "Alice", bob.get_public_hex())

    print_step("Step 3: Poisoned Shared Secrets")
    alice.establish_session(key_for_alice)
    bob.establish_session(key_for_bob)

    print("   [Alice Session]: S_am = (Mallory_Pub)^a mod P")
    print("   [Bob Session]:   S_bm = (Mallory_Pub)^b mod P")

    print_step("Step 4: Interception")
    message = b"Meet me at 9pm."
    encrypted_msg = xor_crypt(message, alice.session_prng)
    delivered_data = net.send("Alice", "Bob", encrypted_msg)

    final_message = xor_crypt(delivered_data, bob.session_prng)
    print_info("Bob received", final_message.decode(errors="replace"))

    if b"3am" in final_message:
        print("\n[DANGER] MITM SUCCESS: Mallory used her private key (m) to decrypt and re-encrypt.")

if __name__ == "__main__":
    main()
