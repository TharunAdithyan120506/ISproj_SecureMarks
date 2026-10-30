"""cryptolab: security and performance analysis of the primitives SecureMarks uses.

Pure library (no web framework): every function takes bytes or numpy arrays and
returns plain dicts, so the portal API, the report CLI and the tests share one
implementation.

    schemes    AES-256 in GCM-SIV / GCM / CTR / CBC / ECB, plus a logistic-map
               chaotic cipher (educational comparison only)
    metrics    entropy, bit/byte difference, chi-square, Pearson, NPCR, UACI, MSE, PSNR
    text       avalanche, key sensitivity (confusion), diffusion map, scheme comparison
    image      RGB pixel encryption and the image security metrics
    hashlab    digests, avalanche, preimage / second-preimage / collision experiments
    signlab    signature generation and verification timing
    perf       timing helpers and size sweeps
    store      every run persisted to data/cryptolab.db
    report     python -m cryptolab.report: run everything, write JSON/CSV/PNG
"""
