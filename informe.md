# Informe - Proyecto Final: Cifrador/Descifrador de Archivos

## Integrantes

- Juan José Díaz  
- Santiago Espinosa  
- Juan Pablo Uribe

## Descripción del proyecto

La consigna asignada para este proyecto final fue desarrollar un programa que permita cifrar y descifrar archivos utilizando criptografía simétrica. El programa debía tener dos funcionalidades principales:

1. **Cifrado de archivos**: el usuario ingresa un archivo y una contraseña. A partir de la contraseña, se genera una clave de 256 bits utilizando el algoritmo PBKDF2. Luego, el archivo debe cifrarse con AES usando esta clave. El archivo resultante debe contener también el hash SHA-256 del archivo original (no cifrado).

2. **Descifrado de archivos**: el usuario proporciona un archivo previamente cifrado y la contraseña utilizada. El programa debe descifrar el archivo y calcular el hash SHA-256 del resultado. Luego, debe comparar este hash con el almacenado en el archivo cifrado, para verificar la integridad del proceso.

## Desarrollo de la solución

Para implementar esta solución, optamos por el lenguaje **Python**, ya que ofrece una sintaxis clara y numerosas librerías de alto nivel para trabajar con criptografía. Para la interfaz gráfica utilizamos la biblioteca **Tkinter**, lo que nos permitió construir un entorno de uso amigable sin desviar la atención de la lógica criptográfica del programa.

El programa implementa un sistema de cifrado y descifrado de archivos utilizando el algoritmo **AES en modo CBC**, con una clave derivada de la contraseña del usuario. Para generar esta clave de 256 bits, utilizamos el algoritmo **PBKDF2** con la función hash SHA-256 y un **salt aleatorio**, lo cual mejora la seguridad al evitar que contraseñas repetidas generen claves idénticas. También se genera un **vector de inicialización (IV)** aleatorio por cada operación de cifrado, como es requerido en el modo CBC para asegurar que no se repitan patrones en los datos cifrados.

Durante el cifrado, se lee el contenido del archivo original, se aplica AES para obtener el texto cifrado, y se calcula su **hash SHA-256**, que será utilizado más adelante para verificar la integridad. Luego, todos los componentes necesarios para el descifrado (extensión original, salt, IV, hash y el texto cifrado) se guardan en un nuevo archivo con la extensión `.enc`. En la fase de descifrado, estos elementos se extraen, se vuelve a derivar la clave usando el mismo algoritmo y salt, y se descifra el contenido. Finalmente, se calcula el hash del archivo restaurado y se compara con el hash original almacenado para confirmar que la información no fue alterada y que la contraseña ingresada es correcta.

Todo esto se implementó mediante una interfaz amigable, que cuenta con tres pestañas principales: una de bienvenida, otra para el proceso de cifrado y una más para el descifrado. A lo largo del uso del programa, se muestran ventanas emergentes (pop-ups) que solicitan información al usuario, como la contraseña, y que notifican si los procesos se realizaron correctamente o si ocurrió algún error.

## Dificultades encontradas

Durante el desarrollo de este proyecto nos enfrentamos a algunas dificultades, aunque logramos resolverlas con éxito tras investigar y repasar los conceptos necesarios. Las principales dificultades fueron las siguientes:

- **Incompatibilidades entre librerías gráficas en distintos sistemas operativos**: Como el equipo trabajaba en diferentes entornos (Windows y Ubuntu), notamos que algunos componentes gráficos de Tkinter se comportaban de forma distinta o generaban errores en ciertos sistemas. Esto nos llevó a realizar pequeñas modificaciones para asegurar la compatibilidad y el correcto funcionamiento de la interfaz en todos los casos.

- **Confusión inicial sobre el funcionamiento del algoritmo AES-CBC**: Al comenzar a implementar el cifrado y descifrado, surgieron dudas sobre los parámetros necesarios para utilizar correctamente AES en modo CBC, como la longitud del IV (vector de inicialización) y su obligatoriedad. Tras revisar la documentación y algunos ejemplos prácticos, logramos entender su uso correcto y ajustar nuestro código en consecuencia.

- **Manejo de archivos binarios y estructuras de datos concatenadas**: Una dificultad adicional fue organizar correctamente la escritura y lectura de los datos cifrados, junto con el IV, el hash y la información auxiliar. Como trabajamos con archivos binarios, fue necesario ser cuidadosos al calcular los offsets y al interpretar cada parte del archivo, para garantizar que el descifrado se realizara sin errores.

## Conclusiones

A partir de este valioso ejercicio pudimos poner en practica los conceptos vistos en la materia de ciberseguridad en un contexto real. A continuación están unas pequeñas conclusiones de lo hecho en este proyecto:

- Aplicamos conceptos clave de criptografía como AES, PBKDF2 y SHA-256 en un caso práctico de cifrado y descifrado de archivos.
    
- Entendimos la importancia del manejo correcto de elementos como el IV, el salt y el hash para garantizar seguridad e integridad.
    
- Incorporamos una interfaz gráfica simple con Tkinter, facilitando el uso del programa para cualquier usuario.
    
- El proyecto reforzó nuestras habilidades en programación segura, trabajo en equipo y uso de buenas prácticas en desarrollo.