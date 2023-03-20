from argparse import ArgumentParser
from typing import Text

from dolabra.analysis.symbolic import SymbolicWrapper
from dolabra.contract_loaders.loader import LoaderType, Loader

# Default analysis arguments
DEFAULT_MAX_DEPTH = 128
DEFAULT_RPC = 'http://127.0.0.1:7545'
DEFAULT_SOLC = 'solc'
DEFAULT_TIMEOUT_ANALYSIS = 60

def init_parser() -> ArgumentParser:
    parser = ArgumentParser(description="Dolabra - an Ethereum Smart Contract Analyzer")
    #parser.add_argument("contract_address", help="The contract address to analyze")
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    # Add analysis parser
    analysis_parser = subparsers.add_parser('analyze', help='begin analysis of a contract')
    init_analysis_parser(analysis_parser)
    return parser

def init_analysis_parser(parser: ArgumentParser) -> None:

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-a', '--address', metavar='ADDRESS', type=Text, help='contract address to analyze')
    input_group.add_argument('-s', '--sol', metavar='PATH', type=Text, dest='sol_path', help='path to solidity contract')
    input_group.add_argument('-b', '--bin', metavar='PATH', type=Text, dest='bin_path',
                             help='path to file containing contract creation bytecode')

    sym_exec_arguments = parser.add_argument_group('symbolic execution arguments')
    sym_exec_arguments.add_argument('--timeout', metavar='SEC', type=int, default=DEFAULT_TIMEOUT_ANALYSIS,
                                    help='symbolic execution timeout (default: {})'.format(DEFAULT_TIMEOUT_ANALYSIS))
    sym_exec_arguments.add_argument('--max-depth', metavar='DEPTH', type=int, default=DEFAULT_MAX_DEPTH,
                                    help='max graph depth (default: {})'.format(DEFAULT_MAX_DEPTH))

    networking_group = parser.add_argument_group('networking arguments')
    networking_group.add_argument('--rpc', metavar="RPC", type=Text, default=DEFAULT_RPC,
                                  help='JSON RPC provider URL (default: \'{}\')'.format(DEFAULT_RPC))

    compilation_group = parser.add_argument_group('compilation arguments')
    compilation_group.add_argument('--solc', metavar='SOLC', type=Text, default=DEFAULT_SOLC,
                                   help='solc binary path (default: \'{}\')'.format(DEFAULT_SOLC))


def analyze(args) -> None:
    # Get the contract loader factory based on the specified options
    if args.bin_path:
        contract_loader = Loader.get_contract(LoaderType.BINARY, path=args.bin_path)
    elif args.sol_path:
        contract_loader = Loader.get_contract(LoaderType.SOLIDITY, path=args.sol_path, solc=args.solc)
    elif args.address:
        contract_loader = Loader.get_contract(LoaderType.JSON_RPC, address=args.address, rpc=args.rpc)
    else:
        raise NotImplementedError('This feature is not available')

    contract = contract_loader.create()
    symbolic_analysis = SymbolicWrapper(contract)
    
    symbolic_analysis.run_analysis()

def main():
    parser = init_parser()
    args = parser.parse_args()

    if args.command == 'analyze':
        analyze(args)
    else:
        parser.print_help()
        exit(1)

if __name__ == "__main__":
    main()
