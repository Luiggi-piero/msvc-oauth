# Esta es una imagen base con Java 17
FROM amazoncorretto:17-alpine-jdk

# (OPCIONAL) Agregando una carpeta de trabajo
# - En la carpeta principal va a crear la carpeta app
# - En app vamos a copiar los elementos
# - Si no esta lo copiara en la raiz
WORKDIR /app

# Puerto que vamos a exponer cuando se levante el contenedor
EXPOSE 9100

# A donde vamos a copiar? 
# donde esta el jar - donde se copiara(es la imagen, usa el mismo/similar nombre del jar origen)
# - La ruta es desde donde se encuentra Dockerfile
# - La ruta inicia desde donde se ubica Dockerfile por eso ./target...
# - El jar se copiara en carpeta home de nuestro SO de la imagen(alpine)
ADD ./target/msvc-oauth-0.0.1-SNAPSHOT.jar msvc-oauth.jar

# Comando a ejecutar para levantar el contenedor
# - se ejecutara java -jar msvc-oauth.jar
# - el comando que se ejecuta automáticamente cuando el contenedor inicia.
# - sirve para levantar tu aplicación Java al iniciar el contenedor.
ENTRYPOINT [ "java", "-jar", "msvc-oauth.jar" ]
