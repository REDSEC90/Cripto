def read_file(file_path: str, binary: bool = True) -> bytes:
    """Lê o conteúdo de um arquivo. Retorna bytes se binary=True, ou str se False."""
    mode = 'rb' if binary else 'r'
    with open(file_path, mode) as f:
        return f.read()

def write_file(file_path: str, data, binary: bool = True) -> None:
    """Escreve dados em um arquivo. Usa modo binário se binary=True, ou texto se False."""
    mode = 'wb' if binary else 'w'
    with open(file_path, mode) as f:
        f.write(data)
