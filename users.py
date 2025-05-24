# Estos son los paquetes que se deben instalar
# pip install pycryptodome
# pip install pyqrcode
# pip install pypng
# pip install pyzbar
# pip install pillow

# No modificar estos módulos que se importan
from optparse import Values
from pyzbar.pyzbar import decode
from PIL import Image
from json import dumps
from json import loads
from hashlib import sha256
from Crypto.Cipher import AES
import base64
import pyqrcode
from os import urandom
import io
from datetime import datetime
import cv2
import numpy as np
import time

# Nombre del archivo con la base de datos de usuarios
usersFileName = "Usuarios.txt"

# Fecha actual
date = None
# Clave aleatoria para encriptar el texto de los códigos QR
key = None

# Función para encriptar (no modificar)
def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

# Función para desencriptar (no modificar)
def decrypt_AES_GCM(encryptedMsg, secretKey):
    (ciphertext, nonce, authTag) = encryptedMsg
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

# Función que genera un código QR (no modificar)
def generateQR(id, program, role, buffer):
    global key
    global date

    data = {'id': id, 'program': program, 'role': role}
    datas = dumps(data).encode("utf-8")

    if key is None:
        key = urandom(32)
        date = datetime.today().strftime('%Y-%m-%d')

    if date != datetime.today().strftime('%Y-%m-%d'):
        key = urandom(32)
        date = datetime.today().strftime('%Y-%m-%d')

    encrypted = list(encrypt_AES_GCM(datas, key))

    qr_text = dumps({
        'qr_text0': base64.b64encode(encrypted[0]).decode('ascii'),
        'qr_text1': base64.b64encode(encrypted[1]).decode('ascii'),
        'qr_text2': base64.b64encode(encrypted[2]).decode('ascii')
    })

    qrcode = pyqrcode.create(qr_text)
    qrcode.png(buffer, scale=8)

# Clases para roles de usuarios
class Usuario:
    def __init__(self, id, program, role):
        self.id = id
        self.program = program
        self.role = role

class Profesor(Usuario):
    def __init__(self, id, program):
        super().__init__(id, program, "profesor")

class Estudiante(Usuario):
    def __init__(self, id, program):
        super().__init__(id, program, "estudiante")

# Clase encargada de detectar espacios disponibles en el parqueadero
def definir_espacios(frame):
    alto = frame.shape[0]
    ancho = frame.shape[1]

    espacios = []
    filas = 2
    columnas = 5
    ancho_rect = ancho // columnas
    alto_rect = alto // 3

    margen_horizontal = 5  # antes 10
    margen_rect_horizontal = 10  # antes 20
    margen_vertical = 30  # antes 40

    for fila in range(filas):
        y = margen_vertical if fila == 0 else alto - alto_rect - margen_vertical
        for col in range(columnas):
            x = col * ancho_rect + margen_horizontal
            espacios.append((x, y, x + ancho_rect - margen_rect_horizontal, y + alto_rect))
    return espacios

def identifySpot(frame):
    espacios = definir_espacios(frame)
    resultados = []

    escala_de_Grises = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    borde = cv2.Canny(escala_de_Grises, 50, 100)

    for i, (x1, y1, x2, y2) in enumerate(espacios):
        region = borde[y1:y2, x1:x2]
        numero_borde = np.count_nonzero(region == 255)

        if numero_borde < 2000:
            estado = "libre"
        else:
            estado = "ocupada"
        resultados.append(f"Plaza {i+1}: {estado}")

    return resultados

# Se debe codificar esta función
def registerUser(id, password, program, role):
    try:
        with open(usersFileName, "a+") as U:
            U.seek(0)
            for linea in U:
                if linea.strip():
                    usuario = loads(linea.strip())
                    if usuario["id"] == id:
                        return "User already registered"

            hashed_password = sha256(password.encode()).hexdigest()
            n_usuario = {
                "id": id,
                "password": hashed_password,
                "program": program,
                "role": role
            }
            U.write(dumps(n_usuario) + "\n")
            return "User successfully registered"
    except:
        return "Error registering user"

# Función que genera el código QR
def getQR(id, password):
    buffer = io.BytesIO()
    hashed_password = sha256(password.encode()).hexdigest()

    try:
        with open(usersFileName, "r") as U:
            for linea in U:
                if linea.strip():
                    usuario = loads(linea.strip())
                    if usuario["id"] == id and usuario["password"] == hashed_password:
                        generateQR(id, usuario["program"], usuario["role"], buffer)
                        return buffer
    except:
        return None

# Función que recibe el código QR como PNG
def sendQR(png):
    try:
        decodedQR = decode(Image.open(io.BytesIO(png)))[0].data.decode('ascii')
        data = loads(decodedQR)
        decrypted = loads(decrypt_AES_GCM(
            (
                base64.b64decode(data["qr_text0"]),
                base64.b64decode(data["qr_text1"]),
                base64.b64decode(data["qr_text2"])
            ), key))

        with open(usersFileName, "r") as U:
            for linea in U:
                if linea.strip():
                    usuario = loads(linea.strip())
                    if usuario["id"] == decrypted["id"]:
                        role = decrypted["role"]
                        program = decrypted["program"]
                        user_obj = Profesor(usuario["id"], program) if role == "profesor" else Estudiante(usuario["id"], program)

                        # Abrir cámara
                        cam = cv2.VideoCapture(0, cv2.CAP_DSHOW)
                        time.sleep(1)
                        ret, frame = cam.read()
                        cam.release()

                        if not ret:
                            return "Error capturando imagen del parqueadero"

                        espacios = definir_espacios(frame)
                        escala_de_Grises = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                        borde = cv2.Canny(escala_de_Grises, 50, 100)

                        libres_profesores = []
                        libres_estudiantes = []
                        estado_espacios = []

                        for i, (x1, y1, x2, y2) in enumerate(espacios):
                            region = borde[y1:y2, x1:x2]
                            numero_borde = np.count_nonzero(region == 255)
                            libre = numero_borde < 2000
                            estado = "libre" if libre else "ocupada"
                            estado_espacios.append(estado)

                            if i < 5 and libre:
                                libres_profesores.append(i + 1)
                            elif i >= 5 and libre:
                                libres_estudiantes.append(i + 1)

                        # Crear texto con estado de plazas para imprimir en QR
                        estado_texto = "; ".join([f"Plaza {i+1}: {estado_espacios[i]}" for i in range(len(estado_espacios))])
                        print(f"Estado plazas detectadas: {estado_texto}")  # Esto sale en consola

                        # Añadir estado de espacios a la info QR
                        data_actualizada = {'id': decrypted["id"], 'program': decrypted["program"], 'role': decrypted["role"], 'estado_plazas': estado_texto}
                        datas = dumps(data_actualizada).encode("utf-8")

                        # Volver a encriptar con la clave global key y generar nuevo QR con info actualizada
                        encrypted = list(encrypt_AES_GCM(datas, key))

                        qr_text = dumps({
                            'qr_text0': base64.b64encode(encrypted[0]).decode('ascii'),
                            'qr_text1': base64.b64encode(encrypted[1]).decode('ascii'),
                            'qr_text2': base64.b64encode(encrypted[2]).decode('ascii')
                        })

                        # Asignar puesto según rol y disponibilidad
                        if role == "profesor" and libres_profesores:
                            return f"Puesto asignado: {libres_profesores[0]}"
                        elif role == "estudiante" and libres_estudiantes:
                            return f"Puesto asignado: {libres_estudiantes[0]}"
                        else:
                            return "No hay puestos disponibles para su rol"

        return "Usuario no registrado"
    except Exception as e:
        return f"Código QR inválido o clave expirada: {str(e)}"

def mostrar_camara_en_vivo():
    
    cam = cv2.VideoCapture(0, cv2.CAP_DSHOW)

    if not cam.isOpened():
        print("No se pudo abrir la cámara.")
        return

    print("Presiona 'q' para salir...")
    while True:
        ret, frame = cam.read()
        if not ret:
            print("No se pudo leer el frame.")
            break

        espacios = definir_espacios(frame)
        libres_profesores, libres_estudiantes = identifySpot(frame)

        gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        display_frame = cv2.cvtColor(gray_frame, cv2.COLOR_GRAY2BGR)

        for i, (x1, y1, x2, y2) in enumerate(espacios):
            estado = "libre"
            if i < 5 and (i + 1) not in libres_profesores:
                estado = "ocupada"
            elif i >= 5 and (i + 1) not in libres_estudiantes:
                estado = "ocupada"

            color = (0, 255, 0) if estado == "libre" else (0, 0, 255)
            cv2.rectangle(display_frame, (x1, y1), (x2, y2))
