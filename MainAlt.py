import time
import socket
import struct
import threading

class FarmBot:
    def __init__(self, Username, Password, IP, Port):
        self.NullByte = struct.pack('B', 0)
        self.BufSize = 4096
        self.InLobby = False
        self.OnlineUsers = {}
        self.OnlineUserMap = {}
        self.IDToUsername = {}
        self.UsernameToID = {}

        self.BadStatusCodes = [400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413,
                               414, 415, 416, 417, 500, 501, 502, 503, 504, 505]
        
        self.NameToIP = {'Europe Block': '45.63.119.253:1031'}

        self.IPToName = {'45.63.119.253:1031': 'Europe Block'}

        self.BotPassword = Password
        self.ServerIP = IP
        self.ServerPort = Port
        self.BotServer = self.IPToName[ '{}:{}'.format(self.ServerIP, self.ServerPort)]
        ctypes.windll.kernel32.SetConsoleTitleW("BBH Farm Bot (auto respawn and death) @Michal")

        self.connectToServer(Username, Password, self.ServerIP, self.ServerPort)

    def sendPacket(self, Socket, PacketData, Receive = False):
        Packet = bytes(PacketData, 'utf-8')

        if Socket:
            Socket.send(Packet + self.NullByte)

            if Receive:
                return Socket.recv(self.BufSize).decode('utf-8')

    def startKeepAlive(self, TimerSeconds = 20):
        if hasattr(self, 'SocketConn'):
            KeepAliveTimer = threading.Timer(TimerSeconds, self.startKeepAlive)
            KeepAliveTimer.daemon = True
            KeepAliveTimer.start()

            self.sendPacket(self.SocketConn, '0')
            
    def startKeepAlt(self, TimerSeconds = 3):
        if hasattr(self, 'SocketConn'):
            KeepAliveTimer = threading.Timer(TimerSeconds, self.startKeepAlt)
            KeepAliveTimer.daemon = True
            KeepAliveTimer.start()

            self.sendPacket(self.SocketConn, '8034021')
            self.sendPacket(self.SocketConn, '61009999'.format(self.BotID))

    def connectionHandler(self):
        Buffer = b''

        while hasattr(self, 'SocketConn'):
            try:
                Buffer += self.SocketConn.recv(self.BufSize)
            except OSError:
                if hasattr(self, 'SocketConn'):
                    self.SocketConn.shutdown(socket.SHUT_RD)
                    self.SocketConn.close()

            if len(Buffer) == 0:
                print('Disconnected')
                break

    def connectToServer(self, Username, Password, ServerIP, ServerPort):
        if Username.lower() == 'PacketBot': # if running multiple bots, set to first one to ensure it doesn't reset the db users status
            self.executeDatabaseQuery("UPDATE users SET status = 0")
            
        try:
            self.SocketConn = socket.create_connection((ServerIP, ServerPort))
        except Exception as Error:
            print(Error)
            return

        Handshake = self.sendPacket(self.SocketConn, '08HxO9TdCC62Nwln1P', True).strip(self.NullByte.decode('utf-8'))

        if Handshake == '08':
            Credentials = '09{};{}'.format(Username, Password)
            RawData = self.sendPacket(self.SocketConn, Credentials, True).split(self.NullByte.decode('utf-8'))

            for Data in RawData:
                if Data.startswith('A'):
                    self.InLobby = True
                    self.BotID = Data[1:][:3]
                    self.BotUsername = Data[4:][:20].replace('#', '')

                    print('Bot Username: {} / Bot ID: {} / Located in {}'.format(self.BotUsername, self.BotID, self.BotServer))

                    EntryPackets = ['02Z900_', '03_', '03GAME', '04GAME', '0k1']

                    for Packet in EntryPackets:
                        self.sendPacket(self.SocketConn, Packet)

                    self.startKeepAlive()
                    ConnectionThread = threading.Thread(target=self.connectionHandler)
                    ConnectionThread.start()
                    self.startKeepAlt()
                    break
                elif Data == '09':
                    print('Incorrect password')
                    break
                elif Data == '091':
                    print('Currently banned')
                    break
        else:
            print('Server capacity check failed')
        
if __name__ == '__main__': # rest in pieces
    FarmBot('PacketBot',  'test', '45.63.119.253', 1031)
    FarmBot('PacketBot1',  'test', '45.63.119.253', 1031)
    FarmBot('PacketBot2',  'test', '45.63.119.253', 1031)
    FarmBot('PacketBot3',  'test', '45.63.119.253', 1031)
    FarmBot('PacketBot4',  'test', '45.63.119.253', 1031)
    FarmBot('PacketBot5',  'test', '45.63.119.253', 1031)
    FarmBot('PacketBot6',  'test', '45.63.119.253', 1031)
    FarmBot('PacketBot7',  'test', '45.63.119.253', 1031)
    FarmBot('PacketBot8',  'test', '45.63.119.253', 1031)
    FarmBot('PacketBot9',  'test', '45.63.119.253', 1031)
    FarmBot('PacketBot10',  'test', '45.63.119.253', 1031)
    FarmBot('PacketBot11',  'test', '45.63.119.253', 1031)
    FarmBot('PacketBot12',  'test', '45.63.119.253', 1031)
    FarmBot('PacketBot13',  'test', '45.63.119.253', 1031)
    FarmBot('PacketBot14',  'test', '45.63.119.253', 1031)
