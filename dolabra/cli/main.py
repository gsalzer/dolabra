import argparse
from dolabra.analysis import run_analysis

def main():
    parser = argparse.ArgumentParser(description="Dolabra Ethereum Smart Contract Analyzer")
    parser.add_argument("contract_address", help="The contract address to analyze")

    args = parser.parse_args()
    run_analysis(args.contract_address)

if __name__ == "__main__":
    main()
