import asyncio
import logging

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko.sign.validation.pdf_embedded import EmbeddedPdfSignature
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.policy_decl import AcceptAllAlgorithms

logging.basicConfig(
    # level=logging.DEBUG,
    format="[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s",
)


async def main():
    from rssp import load_rssp

    options = load_rssp()
    chain = options["chain"]
    signer = options["signer"]

    print("\n\n" + "=" * 20 + " RUN " + "=" * 20 + "\n\n")

    with open("input.pdf", "rb") as inf:
        w = IncrementalPdfFileWriter(inf)
        validation_context = ValidationContext(
            allow_fetching=False,
            trust_roots=[chain[-1]],
            other_certs=chain,
            algorithm_usage_policy=AcceptAllAlgorithms(),
        )

        meta = signers.PdfSignatureMetadata(
            field_name="MobileIdVnExample",
            subfilter=SigSeedSubFilter.PADES,
            validation_context=validation_context,
            embed_validation_info=False,
            use_pades_lta=False,
        )
        with open("output.pdf", "wb") as outf:
            await signers.async_sign_pdf(
                w,
                meta,
                signer=signer,
                output=outf,
            )

        print("\n\n============ VALIDATION ============")
        with open("output.pdf", "rb") as outf:
            r = PdfFileReader(outf)
            sig: EmbeddedPdfSignature = r.embedded_signatures[0]

            print("VALIDATION DIGEST:", sig.compute_digest())
            status = await async_validate_pdf_signature(
                sig,
                validation_context,
            )

            print(status.pretty_print_details())


asyncio.run(main())
