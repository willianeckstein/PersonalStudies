from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def generate_keys():
    private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public = private.public_key()

    return (private, public)


def sign(message, private):
    sig = private.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return sig


def verify(message, sig, public):
    try:
        public.verify(
            sig,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        print("Error on public key verification")
        return False


if __name__ == '__main__':
    pr, pu = generate_keys()
    message = b'This is a secret message'
    sig = sign(message, pr)
    correct = verify(message, sig, pu)

    if correct:
        print("Success! Good signature")
    else:
        print("Error! Signature is bad")
