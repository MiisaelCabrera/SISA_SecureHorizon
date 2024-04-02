# Usa la imagen base de Python
FROM python:3.9

# Establece el directorio de trabajo en /app
WORKDIR /app

# Copia el archivo de requisitos al contenedor
COPY requirements.txt .

# Instala las dependencias
RUN pip install -r requirements.txt

# Copia el código actual al contenedor
COPY . .

# Comando a ejecutar cuando se inicie el contenedor
CMD ["python", "app.py"]
