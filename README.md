# esp-idf-btc
Simple Bitcoin miner with a light-weight Stratum TCP client, built for the ESP-32. The program leverages ESP-32's dual-core CPU, assigning the network responsibilities(connecting to a Stratum pool, listening for new jobs and submitting succesful jobs) to one core and SHA-256 computation + Merkle tree reconstruction to the other.

(Note: this is an extremely impractical learning/hobby project, with some napkin math, this setup should yield 0.0000001 USD worth of Bitcoin per year, paying off an ESP-32 in about 20 million years.)
