import argparse
from dolabra.analysis.symbolic import SymbolicWrapper

def main():
    parser = argparse.ArgumentParser(description="Dolabra Ethereum Smart Contract Analyzer")
    parser.add_argument("contract_address", help="The contract address to analyze")

    args = parser.parse_args()
    symbolic_analysis = SymbolicWrapper(args.contract_address)
    
    symbolic_analysis.run_analysis()

if __name__ == "__main__":
    main()
