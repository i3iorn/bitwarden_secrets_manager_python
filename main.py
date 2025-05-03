import logging
from bitwarden_secrets_manager_python import BWS

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    bws = BWS(
        silent_install=True,
        bws_access_token=r"0.66e614cd-0aef-495c-a074-b2d2005ed396.pomd7wRCv4LsuMsVUnBRybmW4InRMo:QWYDqaIDc0BxQsiCRIDpeg=="
    )
    print(bws.get_secret("6c54ce77-0efb-4fd9-9b76-b2a1006338c9"))
