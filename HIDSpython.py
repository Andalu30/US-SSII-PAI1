import hashlib
import os
import logging
import matplotlib
import matplotlib.pyplot as plt
import datetime
import requests
from cryptography.fernet import Fernet
from time import sleep
from daemonize import Daemonize
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4


logFilename = "/var/log/PAI1.log"
logging.basicConfig(filename=logFilename,level=logging.DEBUG,format='%(asctime)s:%(levelname)s:%(message)s')

key = Fernet.generate_key()
fernet = Fernet(key)


tiempoEsperaDemonio = 30


fallosActualesParaKPI = {datetime.datetime.now():0}
porcentajeActualesParaKPI = {datetime.datetime.now():0}

bot_token = ''
bot_chatID = ''


def notificaError(msg, token='', chatID=''):
    logging.warning(msg)

    send_text = 'https://api.telegram.org/bot' + token + '/sendMessage?chat_id=' + chatID + '&parse_mode=Markdown&text=' + msg
    response = requests.get(send_text)




def ConfigFile():
    def creaConfigFile():
        logging.info("Creando archivo de configuracion en /etc/SSIIPAI1. Defina los archivos que hay que comprobar.")
        os.makedirs("/etc/SSII-PAI1/", 0o0755)
        string_config=";Algoritmo\n" \
                     "SHA1\n" \
                     ";Tiempo\n" \
                     "1m\n" \
                     ";Nombre Fichero salida\n" \
                     "SSIIoutputKPI.pdf\n" \
                     ";Token Bot Telegram\n"\
                     "\n"\
                     ";Chat id Telegram\n"\
                     "\n"\
                     ";Ficheros\n"
        text_file = open("/etc/SSII-PAI1/SSIIPAI1.cfg", "w")
        text_file.write(string_config)
        text_file.close()
        tiempoEsperaDemonio=60

    def leeConfigFile():

        def cantidadHashesGuardos():

            file = open("/etc/SSII-PAI1/hashes.cfg", "rb")
            encrypted = file.read()
            file.close()

            try:
                decrypted = fernet.decrypt(encrypted)
                logging.debug(decrypted.decode('utf-8'))
                logging.debug("CantidadHashesGuardados: {}".format(len(decrypted.decode("utf-8").split('\n'))))
                logging.debug(decrypted.decode("utf-8").split('\n'))
                return len(decrypted.decode("utf-8").split('\n'))
            except:
                os.remove("/etc/SSII-PAI1/hashes.cfg")
                notificaError("Error al desencriptar el archivo de hashes. Creando uno nuevo",bot_token,bot_chatID)
                return 0






        logging.info("Cargando archivo de configuracion")
        text_file = open("/etc/SSII-PAI1/SSIIPAI1.cfg", "r")

        argumentos = []
        for line in text_file:
            li = line.strip()
            if not li.startswith(";"):
                argumentos.append(li)
                line.rstrip()

        logging.debug(argumentos[3])
        logging.debug(argumentos[4])

        bot_token, bot_chatID = argumentos[3], argumentos[4]

        logging.debug(bot_token)
        logging.debug(bot_chatID)

        archivos = argumentos[5:]

        logging.debug(argumentos[1])
        tiempoEsperaDemonio = configuraDemonio(argumentos[1])



        if os.path.isfile("/etc/SSII-PAI1/hashes.cfg"):
            if (len(archivos) == cantidadHashesGuardos()):
                getHashfromFile(argumentos[0], archivos,argumentos[2],comprueba=True)
            else:
                getHashfromFile(argumentos[0], archivos,argumentos[2])
        else:
            getHashfromFile(argumentos[0], archivos,argumentos[2])




    if(os.path.isfile("/etc/SSII-PAI1/SSIIPAI1.cfg")):
        # Si existe el archivo de configuracion leerlo y continuar, sino, crearlo
        leeConfigFile()
    else:
        creaConfigFile()





def getHashfromFile(tipoHash, archivos,outputfilename,comprueba=False):
    hashes = []

    try:
        if tipoHash  == "SHA1":
            for archivo in archivos:
                hash = hashlib.sha1(open(archivo,'rb').read())
                hashes.append(hash.hexdigest())
        elif tipoHash == "MD5":
            for archivo in archivos:
                hash = hashlib.md5(open(archivo,'rb').read())
                hashes.append(hash.hexdigest())
        elif tipoHash == "SHA256":
            for archivo in archivos:
                hash = hashlib.sha256(open(archivo, 'rb').read())
                hashes.append(hash.hexdigest())
        elif tipoHash == "SHA512":
            for archivo in archivos:
                hash = hashlib.sha512(open(archivo, 'rb').read())
                hashes.append(hash.hexdigest())
    except:
        notificaError("Error al leer los archivos que se deben comprobar",bot_token,bot_chatID)

    if comprueba == False:
        logging.info("Guardando nuevos hashes en el archivo de cofiguracion")
        text_file = open("/etc/SSII-PAI1/hashes.cfg", "wb")
        stringAguardar = ""
        for hash in hashes:
            stringAguardar = stringAguardar+"{}\n".format(hash)
        stringAguardar = stringAguardar[:-1]

        #logging.debug("hashesqueseguardanencryptados {}".format(stringAguardar))
        encrypted = fernet.encrypt(stringAguardar.encode())
        text_file.write(encrypted)
        text_file.close()

    else:
        compruebaSHAs(tipoHash, archivos,outputfilename)










def compruebaSHAs(tipoHash, archivos,outputfilename):
    file = open("/etc/SSII-PAI1/hashes.cfg","rb")
    encrypted = file.read()
    file.close()
    logging.debug("Encrypted: {}".format(encrypted))
    try:
        decrypted = fernet.decrypt(encrypted)
    except:
        logging.warning("Error al desencriptar el archivo de hashes. Creando uno nuevo")
        os.remove("/etc/SSII-PAI1/hashes.cfg")
        pass

    #logging.debug("Decrypted {}".format(decrypted.decode("utf-8")))
    hashesGuardados = []
    for line in decrypted.decode("UTF-8").split('\n'):
        logging.debug(line)
        hashesGuardados.append(line.strip("\n"))

    hahesArchivos = []


    try:

        if tipoHash == "SHA1":
            for archivo in archivos:
                hash = hashlib.sha1(open(archivo,'rb').read())
                hahesArchivos.append(hash.hexdigest())

        elif tipoHash == "MD5":
            for archivo in archivos:
                hash = hashlib.md5(open(archivo,'rb').read())
                hahesArchivos.append(hash.hexdigest())
        elif tipoHash == "SHA256":
            for archivo in archivos:
                hash = hashlib.sha256(open(archivo,'rb').read())
                hahesArchivos.append(hash.hexdigest())
        elif tipoHash == "SHA512":
            for archivo in archivos:
                hash = hashlib.sha512(open(archivo,'rb').read())
                hahesArchivos.append(hash.hexdigest())

        #logging.debug(hahesArchivos, hashesGuardados)

        fallos = []
        for i in range(len(hahesArchivos)):
            if hashesGuardados[i] != hahesArchivos[i]:
                fallos.append(i)
            else:
                continue

        if len(fallos)!=0:
            generaKPIs(fallos, archivos, outputfilename)
        else:
            todoBien(outputfilename)
    except:
        notificaError("Error al leer los archivos",bot_token,bot_chatID)


def todoBien(outputfilename):
    logging.debug("Porcentaje de errores: {}".format("0"))
    logging.debug("Todo bien de momento :)")
    fallosActualesParaKPI[datetime.datetime.now()] = 0
    porcentajeActualesParaKPI[datetime.datetime.now()] = 0


    t = list(fallosActualesParaKPI.keys())
    s = list(fallosActualesParaKPI.values())
    fig, ax = plt.subplots()
    ax.plot(t, s)
    ax.set(xlabel='Hora del reporte', ylabel='Cantidad de errores',
           title='Número de errores cada vez que se comprueba')
    ax.grid()
    fig.savefig("NumeroFicherosError.png")
    plt.show()


    t = list(porcentajeActualesParaKPI.keys())
    s = list(porcentajeActualesParaKPI.values())
    fig, ax = plt.subplots()
    ax.plot(t, s)
    ax.set(xlabel='Hora del reporte', ylabel='Porcentaje de errores',
           title='Porcentaje de errores cada vez que se comprueba')
    ax.grid()
    fig.savefig("PorcentajeErrores.png")
    plt.show()



    w, h = A4
    c = canvas.Canvas(outputfilename, pagesize=A4)
    c.drawString(50, h - 50, "Fichero de indicadores KPI")
    c.drawString(250, h - 50, "{}".format(datetime.datetime.now()))
    c.drawString(50, h - 100, "Todo bien de momento")
    c.drawString(50, h - 200, "Graficas:")
    c.drawImage("NumeroFicherosError.png", 150, h - 450, width=350, height=250)
    c.drawImage("PorcentajeErrores.png", 150, h - 700, width=350, height=250)


    c.showPage()
    c.save()





def generaKPIs(fallos,archivos,outputfilename):

    for fallo in fallos:
        notificaError("El archivo {} ha fallado".format(archivos[fallo]),bot_token,bot_chatID)



    porcentaje = len(fallos)/len(archivos)*100
    logging.debug("Porcentaje de errores: {}".format(porcentaje))

    fallosActualesParaKPI[datetime.datetime.now()] = len(fallos)
    porcentajeActualesParaKPI[datetime.datetime.now()] = int(porcentaje)



    t = list(fallosActualesParaKPI.keys())
    s = list(fallosActualesParaKPI.values())
    fig, ax = plt.subplots()
    ax.plot(t, s)
    ax.set(xlabel='Hora del reporte', ylabel='Cantidad de errores',
           title='Número de errores cada vez que se comprueba')
    ax.grid()
    fig.savefig("NumeroFicherosError.png")
    plt.show()


    t = list(porcentajeActualesParaKPI.keys())
    s = list(porcentajeActualesParaKPI.values())
    fig, ax = plt.subplots()
    ax.plot(t, s)
    ax.set(xlabel='Hora del reporte', ylabel='Porcentaje de errores',
           title='Porcentaje de errores cada vez que se comprueba')
    ax.grid()
    fig.savefig("PorcentajeErrores.png")
    plt.show()



    w, h = A4
    c = canvas.Canvas(outputfilename, pagesize=A4)
    c.drawString(50, h - 50, "Fichero de indicadores KPI")
    c.drawString(250, h - 50, "{}".format(datetime.datetime.now()))

    c.drawString(50, h - 75,"Porcentaje de errores: {}".format(porcentaje))

    y = 100
    for fallo in fallos:
        c.drawString(50, h - y,"El archivo {} ha fallado".format(archivos[fallo]))
        y = y + 10


    c.drawString(50, h - 200, "Graficas:")
    c.drawImage("NumeroFicherosError.png", 150, h - 450, width=350, height=250)
    c.drawImage("PorcentajeErrores.png", 150, h - 700, width=350, height=250)


    c.showPage()
    c.save()














def configuraDemonio(tiempoString):
    if tiempoString.endswith("h"):
        tiempo = 3600*tiempoString[:-1]
    elif tiempoString.endswith("m"):
        tiempo = 60*tiempoString[:-1]
    elif tiempoString.endswith("s"):
        tiempo = tiempoString[:-1]
    elif tiempoString.endswith("d"):
        tiempo = 3600*24*tiempoString[:-1]
        logging.debug("Tiempo: {}".format(tiempo))
    return tiempo



def main():
    while True:
        ConfigFile()
        sleep(tiempoEsperaDemonio)

pid = "/tmp/test.pid"
daemon = Daemonize(app="PAI1", pid=pid, action=main())
daemon.start()


