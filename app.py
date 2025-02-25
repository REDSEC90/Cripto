from flask import Flask, request, render_template, send_file, Response
from crypto_utils import encrypt_data, decrypt_data
from file_utils import read_file, write_file
import os

app = Flask(__name__)

# Pasta temporária para armazenar arquivos processados
UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route("/", methods=["GET"])
def index():
    """Renderiza a página inicial com o formulário."""
    return render_template("index.html")

@app.route("/process", methods=["POST"])
def process_file():
    """Processa o arquivo enviado (criptografar ou descriptografar)."""
    try:
        # Obtém os dados do formulário
        file = request.files["file"]
        password = request.form["password"]
        action = request.form["action"]

        if not file or not password:
            return "Erro: Arquivo ou senha não fornecidos.", 400

        # Salva o arquivo temporariamente
        input_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(input_path)

        # Define o caminho de saída
        output_filename = f"processed_{file.filename}"
        output_path = os.path.join(UPLOAD_FOLDER, output_filename)

        # Lê o arquivo de entrada
        if action == "encrypt":
            plaintext = read_file(input_path, binary=True)
            encoded_data = encrypt_data(plaintext, password)
            write_file(output_path, encoded_data, binary=False)
            mime_type = "text/plain"
        elif action == "decrypt":
            encoded_data = read_file(input_path, binary=False)
            plaintext = decrypt_data(encoded_data, password)
            write_file(output_path, plaintext, binary=True)
            mime_type = "application/octet-stream"
        else:
            return "Erro: Ação inválida.", 400

        # Remove o arquivo de entrada temporário
        os.remove(input_path)

        # Envia o arquivo processado para download
        return send_file(
            output_path,
            as_attachment=True,
            download_name=output_filename,
            mimetype=mime_type
        )

    except Exception as e:
        return f"Erro durante o processamento: {str(e)}", 500

    finally:
        # Limpeza: Remove arquivos temporários, se existirem
        if os.path.exists(output_path):
            os.remove(output_path)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
