# pip install opencv-python
import cv2
import numpy as np
import time
ultimo_update = 0
intervalo = 30  # segundos

# Open the default camera
cam = cv2.VideoCapture(0,cv2.CAP_DSHOW)

# Get the default frame width and height
frame_width = int(cam.get(cv2.CAP_PROP_FRAME_WIDTH))
frame_height = int(cam.get(cv2.CAP_PROP_FRAME_HEIGHT))

# Crea 10 rectángulos
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

        

while True:
    # Read frame from camera
    ret, frame = cam.read()

    ahora = time.time()
    if ahora - ultimo_update >= intervalo:
        a = identifySpot(frame)
        ultimo_update = ahora
        for estado in a:
            print(estado)

    # Procesar para visual
    espacios = definir_espacios(frame)
    escala_de_Grises = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    borde = cv2.Canny(escala_de_Grises, 50, 100)

    for i, (x1, y1, x2, y2) in enumerate(espacios):
        region = borde[y1:y2, x1:x2]
        numero_borde = np.count_nonzero(region == 255)
        estado = "Libre" if numero_borde < 2000 else "Ocupada"
        color = (0, 255, 0) if estado == "Libre" else (0, 0, 255)
        cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)
        cv2.putText(frame, f"{i+1}: {estado}", (x1 + 5, y1 + 20), 
                    cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 1)

    cv2.imshow('Parking Lot Camera', cv2.flip(frame, 1))
    cv2.imshow('Bordes Detectados', cv2.flip(borde, 1))

    if cv2.waitKey(10) != -1:
        break

    #print(len(frame))
    
    # Display the captured frame after flipping
    cv2.imshow('Parking Lot Camera', cv2.flip(frame,1))  
    
    a = identifySpot(frame)

    borde = cv2.Canny(frame, 50, 100)
    
    cv2.imshow('Bordes Detectados', cv2.flip(borde, 1))
    for estado in a:
        print(estado)

    # Wait for 10ms and exit if any key is pressed
    if cv2.waitKey(10) != -1:
        break

# Release the capture object
cam.release()
cv2.destroyAllWindows()
