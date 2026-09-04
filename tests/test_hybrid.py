"""Hybrid envelope round-trips, including examples/sample.txt."""
from pathlib import Path
import pytest
from cryptography.exceptions import InvalidTag
from cryptolab.hybrid import MAGIC,hybrid_decrypt,hybrid_decrypt_file,hybrid_encrypt,hybrid_encrypt_file,unpack_envelope
from cryptolab.modern.rsa import generate_rsa_keypair

def _sample_path(): return Path(__file__).resolve().parents[1]/"examples"/"sample.txt"
  def test_hybrid_bytes_round_trip():
        priv,pub=generate_rsa_keypair(2048); pt=b"envelope payload"; package=hybrid_encrypt(pt,pub)
        assert package.startswith(MAGIC); assert hybrid_decrypt(package,priv)==pt
        wrapped,blob=unpack_envelope(package); assert len(wrapped)>0; assert len(blob)>12
    def test_hybrid_file_sample_txt(tmp_path):
          src=_sample_path(); assert src.is_file(),f"missing {src}"; original=src.read_bytes(); priv,pub=generate_rsa_keypair(2048)
          enc=tmp_path/"sample.txt.enc"; out=tmp_path/"sample.out.txt"; hybrid_encrypt_file(src,enc,pub)
          assert enc.is_file(); assert enc.read_bytes()!=original; hybrid_decrypt_file(enc,out,priv); assert out.read_bytes()==original
      def test_hybrid_wrong_recipient():
            priv_a,pub_a=generate_rsa_keypair(2048); priv_b,_=generate_rsa_keypair(2048); package=hybrid_encrypt(b"secret",pub_a)
            with pytest.raises(Exception): hybrid_decrypt(package,priv_b)
              def test_hybrid_rejects_bad_magic():
                    priv,pub=generate_rsa_keypair(2048); package=bytearray(hybrid_encrypt(b"x",pub)); package[0]^=0xFF
                    with pytest.raises(ValueError,match="magic"): hybrid_decrypt(bytes(package),priv)
                      def test_hybrid_rejects_truncated():
                            with pytest.raises(ValueError,match="truncated"): unpack_envelope(b"CLB")
                              def test_hybrid_tamper_payload():
                                    priv,pub=generate_rsa_keypair(2048); package=bytearray(hybrid_encrypt(b"payload",pub)); package[-1]^=1
                                    with pytest.raises(InvalidTag): hybrid_decrypt(bytes(package),priv)
                                      
