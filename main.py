import argparse
from crypto_utils import encrypt_data, decrypt_data
from file_utils import read_file, write_file

def parse_arguments():
    """Configura e retorna os argumentos da linha de comando."""
    parser = argparse.ArgumentParser(description="Script para criptografar/comprimir/codificar e o inverso.")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Parser para encriptação
    parser_encrypt = subparsers.add_parser('encrypt', help="Criptografa um arquivo.")
    parser_encrypt.add_argument('--input', '-i', required=True, help="Caminho do arquivo de entrada (texto plano).")
    parser_encrypt.add_argument('--output', '-o', required=True, help="Caminho do arquivo de saída (dados codificados).")
    parser_encrypt.add_argument('--password', '-p', required=True, help="Senha para criptografia.")

    # Parser para decriptação
    parser_decrypt = subparsers.add_parser('decrypt', help="Descriptografa um arquivo.")
    parser_decrypt.add_argument('--input', '-i', required=True, help="Caminho do arquivo de entrada (dados codificados).")
    parser_decrypt.add_argument('--output', '-o', required=True, help="Caminho do arquivo de saída (texto decifrado).")
    parser_decrypt.add_argument('--password', '-p', required=True, help="Senha para decriptação.")

    return parser.parse_args()

def main():
    """Coordenada o fluxo de criptografia ou descriptografia."""
    args = parse_arguments()

    if args.command == 'encrypt':
        try:
            plaintext = read_file(args.input, binary=True)
            encoded_data = encrypt_data(plaintext, args.password)
            write_file(args.output, encoded_data, binary=False)
            print("Arquivo criptografado, comprimido e codificado com sucesso.")
        except Exception as e:
            print(f"Erro durante a encriptação: {e}")

    elif args.command == 'decrypt':
        try:
            encoded_data = read_file(args.input, binary=False)
            plaintext = decrypt_data(encoded_data, args.password)
            write_file(args.output, plaintext, binary=True)
            print("Arquivo decodificado, descomprimido e descriptografado com sucesso.")
        except Exception as e:
            print(f"Erro durante a decriptação: {e}")

if __name__ == "__main__":
    main()
