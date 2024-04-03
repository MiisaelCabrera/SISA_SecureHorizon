# Usar la imagen de node como base
FROM node:18-alpine

# Establecer el directorio de trabajo en /app
WORKDIR /app

# Copiar el archivo de configuración del proyecto y las dependencias
COPY sh_user_interface/package.json sh_user_interface/package-lock.json ./

# Instalar las dependencias
RUN npm install

# Copiar el código del proyecto
COPY sh_user_interface .

# Compilar el proyecto
RUN npm run build

# Exponer el puerto en el que funciona la aplicación
EXPOSE 3000

# Comando para ejecutar la aplicación
CMD ["npm", "start"]
