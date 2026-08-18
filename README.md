# esp-idf-btc
Simple Bitcoin miner with a lightweight Stratum TCP client, built for the ESP-32. The program leverages the ESP-32's dual-core CPU, assigning the network responsibilities (connecting to a Stratum pool, listening for new jobs, and submitting successful jobs) to one core, and SHA-256 computation + Merkle tree reconstruction to the other.

(With some napkin math, this setup should yield about $0.0000001 USD worth of Bitcoin per year, paying off an ESP-32 in about 20 million years.)
