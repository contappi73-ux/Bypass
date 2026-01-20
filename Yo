import os
import sys
import datetime
import stat

# ==============================================================================
# CONFIGURAÇÃO DE AUDITORIA
# ==============================================================================
# Ferramenta: Forensic Audit Tool (Free Fire Focus)
# Versão: 5.0 (Production Ready - No Placebos)
# Autor: yone_zzj
# Objetivo: Análise estática de sistema de arquivos (Read-Only)
# ==============================================================================

class Config:
    # Assinaturas baseadas em nomes de arquivos reais de ferramentas conhecidas
    SIG_ARQUIVOS_SUSPEITOS = [
        "ff4x", "mod_menu", "inject", "bypass", "aimlock", 
        "head_track", "regedit", "panel_vip", "auxilio_mi", 
        "antiban", "dark_team", "ps_team"
    ]
    
    # Pacotes alvo
    PACOTES_FF = ["com.dts.freefireth", "com.dts.freefiremax"]
    
    # Parâmetros Técnicos
    MAX_SIZE_CONFIG_XML = 1024 * 1024  # 1 MB (Acima disso é anomalia técnica em XML)
    WINDOW_MODIFICACAO_RECENTE = 7     # Dias
    
    # Cores para terminal
    C_RED = '\033[91m'
    C_YEL = '\033[93m'
    C_GRN = '\033[92m'
    C_CYAN = '\033[96m'
    C_RST = '\033[0m'

class Relatorio:
    def __init__(self, caminho_base):
        self.caminho_base = caminho_base
        self.logs = []
        self.score_risco = 0
        self.erros_permissao = 0

    def add_log(self, tipo, msg, pontos_risco, data_ref=None):
        entry = {
            "tipo": tipo,
            "msg": msg,
            "pontos": pontos_risco,
            "data": data_ref
        }
        self.logs.append(entry)
        self.score_risco += pontos_risco

# ==============================================================================
# FUNÇÕES AUXILIARES REAIS (SISTEMA DE ARQUIVOS)
# ==============================================================================

def validar_acesso(caminho):
    """Verifica se o script tem permissão real de leitura no diretório."""
    if not os.path.exists(caminho):
        return False, "Diretório não existe"
    try:
        os.listdir(caminho)
        return True, "Acesso OK"
    except PermissionError:
        return False, "Permissão Negada (Restrição do Android/SO)"
    except OSError as e:
        return False, f"Erro de I/O: {str(e)}"

def format_data(timestamp):
    if not timestamp: return "N/A"
    return datetime.datetime.fromtimestamp(timestamp).strftime('%d/%m/%Y %H:%M:%S')

def get_file_stats(filepath):
    """Retorna stats brutos. Falha silenciosamente se arquivo sumir durante a execução."""
    try:
        return os.stat(filepath)
    except OSError:
        return None

# ==============================================================================
# MÓDULOS DE ANÁLISE (BASEADOS EM FATOS TÉCNICOS)
# ==============================================================================

def analisar_estrutura_obb(base_path, relatorio):
    """
    Verifica a pasta OBB.
    Fato Técnico: A Google Play entrega apenas arquivos .obb.
    Anomalia: Presença de .cfg, .txt, .lua ou múltiplos .obb.
    """
    path_obb = os.path.join(base_path, "Android", "obb")
    
    acesso, msg = validar_acesso(path_obb)
    if not acesso:
        relatorio.erros_permissao += 1
        return # Não especula se não pode ler

    for pacote in Config.PACOTES_FF:
        target = os.path.join(path_obb, pacote)
        if os.path.exists(target):
            try:
                files = os.listdir(target)
                arquivos_estranhos = [f for f in files if not f.endswith(".obb")]
                
                # Verifica OBBs modificados recentemente
                for f in files:
                    full_p = os.path.join(target, f)
                    stats = get_file_stats(full_p)
                    if stats:
                        dias_diff = (datetime.datetime.now().timestamp() - stats.st_mtime) / 86400
                        if dias_diff < Config.WINDOW_MODIFICACAO_RECENTE:
                            relatorio.add_log(
                                "MODIFICAÇÃO RECENTE (OBB)",
                                f"Arquivo core modificado há {int(dias_diff)} dias: {f}",
                                3, stats.st_mtime
                            )

                if arquivos_estranhos:
                    relatorio.add_log(
                        "ESTRUTURA OBB IRREGULAR",
                        f"Arquivos não-nativos detectados: {arquivos_estranhos}",
                        5 # Alto risco
                    )
            except PermissionError:
                relatorio.erros_permissao += 1

def analisar_anomalia_shared_prefs(base_path, relatorio):
    """
    Verifica shared_prefs.
    Fato Técnico: Arquivos XML de preferência são texto puro e leves (<50KB).
    Anomalia: Arquivos > 1MB indicam injeção de base64 ou arrays de strings (método Holograma).
    """
    path_data = os.path.join(base_path, "Android", "data")
    
    acesso, msg = validar_acesso(path_data)
    if not acesso:
        relatorio.add_log("ALERTA DE SISTEMA", f"Não foi possível ler /Android/data: {msg}", 0)
        relatorio.erros_permissao += 1
        return

    for pacote in Config.PACOTES_FF:
        # Tenta os dois caminhos comuns dependendo da versão do Unity/Android
        paths_possiveis = [
            os.path.join(path_data, pacote, "files", "shared_prefs"),
            os.path.join(path_data, pacote, "shared_prefs")
        ]
        
        for p in paths_possiveis:
            if os.path.exists(p):
                try:
                    for f in os.listdir(p):
                        if f.endswith(".xml"):
                            full_p = os.path.join(p, f)
                            stats = get_file_stats(full_p)
                            if stats:
                                if stats.st_size > Config.MAX_SIZE_CONFIG_XML:
                                    size_mb = stats.st_size / (1024 * 1024)
                                    relatorio.add_log(
                                        "ANOMALIA VOLUMÉTRICA (XML)",
                                        f"Arquivo de configuração excessivamente grande: {f} ({size_mb:.2f} MB)",
                                        4, stats.st_mtime
                                    )
                                
                                # Verifica nomes de arquivos conhecidos de cheats
                                f_lower = f.lower()
                                if any(x in f_lower for x in ["painel", "regedit", "holo"]):
                                    relatorio.add_log(
                                        "ASSINATURA DE ARQUIVO SUSPEITA",
                                        f"Nome de arquivo de config coincide com cheat: {f}",
                                        5, stats.st_mtime
                                    )
                except PermissionError:
                    pass

def analisar_residuos_gerais(base_path, relatorio):
    """
    Varre Downloads e Documentos buscando instaladores e scripts.
    """
    pastas_alvo = ["Download", "Documents", "Documentos"]
    
    for pasta in pastas_alvo:
        target = os.path.join(base_path, pasta)
        if os.path.exists(target):
            try:
                # Walk limitado para não travar em diretórios gigantes
                for root, dirs, files in os.walk(target):
                    # Limita profundidade a 2 níveis
                    level = root.replace(target, '').count(os.sep)
                    if level > 2: continue
                    
                    for f in files:
                        f_low = f.lower()
                        # Busca por assinaturas no nome
                        for sig in Config.SIG_ARQUIVOS_SUSPEITOS:
                            if sig in f_low:
                                relatorio.add_log(
                                    "ARQUIVO COM ASSINATURA CONHECIDA",
                                    f"Encontrado em {pasta}: {f}",
                                    5
                                )
                        
                        # OBB solto em Downloads (indica movimentação manual)
                        if f_low.endswith(".obb") and "main" in f_low:
                            relatorio.add_log(
                                "ARQUIVO DE SISTEMA DESLOCADO",
                                f"OBB encontrado em pasta de usuário: {os.path.join(root, f)}",
                                2
                            )
            except PermissionError:
                pass

def analisar_ambiente_permissivo(base_path, relatorio):
    """
    Verifica a existência de pastas de ferramentas de Root/Modding.
    Isso classifica o AMBIENTE, não acusa o usuário de cheat.
    """
    pastas_root = ["Magisk", "TWRP", "TitaniumBackup", "MT2", "LuckyPatcher"]
    path_shizuku = os.path.join(base_path, "Android", "data", "moe.shizuku.privileged.api")
    
    try:
        itens_raiz = os.listdir(base_path)
        for item in itens_raiz:
            if item in pastas_root:
                relatorio.add_log(
                    "AMBIENTE PERMISSIVO (ROOT/TOOLS)",
                    f"Diretório de ferramenta de sistema encontrado: {item}",
                    1 # Baixo risco, apenas contexto
                )
    except OSError:
        pass

    # Verifica Shizuku (Muitos cheats modernos usam Shizuku para injetar sem root completo)
    if os.path.exists(path_shizuku):
         relatorio.add_log(
            "AMBIENTE DEPURAÇÃO (SHIZUKU)",
            "Pasta de dados do Shizuku detectada. Permite operações de sistema sem root.",
            1
        )

# ==============================================================================
# EXECUÇÃO E REPORT
# ==============================================================================

def gerar_relatorio_final(relatorio):
    print("\n" + "="*60)
    print(f"{Config.C_CYAN}RELATÓRIO DE AUDITORIA TÉCNICA (FORENSE v5.0){Config.C_RST}")
    print(f"Data: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}")
    print(f"Alvo: {relatorio.caminho_base}")
    print("="*60)

    if relatorio.erros_permissao > 0:
        print(f"{Config.C_YEL}[!] ALERTA DE INTEGRIDADE:{Config.C_RST} Ocorreram {relatorio.erros_permissao} erros de permissão.")
        print("    O Android (11+) pode estar bloqueando a leitura de /Android/data.")
        print("    Para análise completa, é necessário acesso total aos arquivos.")
        print("-" * 60)

    if not relatorio.logs:
        print(f"{Config.C_GRN}>> NENHUMA ANOMALIA TÉCNICA DETECTADA NOS DIRETÓRIOS ACESSÍVEIS.{Config.C_RST}")
    else:
        # Ordenar por gravidade
        logs_ordenados = sorted(relatorio.logs, key=lambda x: x['pontos'], reverse=True)
        
        for log in logs_ordenados:
            cor = Config.C_RED if log['pontos'] >= 4 else Config.C_YEL
            tag_data = f" | Data Ref: {format_data(log['data'])}" if log['data'] else ""
            
            print(f"{cor}[{log['tipo']}]{Config.C_RST} (Score: +{log['pontos']})")
            print(f"   > Detalhe: {log['msg']}{tag_data}")
            print("-" * 60)

    # Classificação Final
    print(f"\n{Config.C_CYAN}SCORE ACUMULADO: {relatorio.score_risco}{Config.C_RST}")
    if relatorio.score_risco == 0:
        print("Classificação: LIMPO / SEM DADOS SUFICIENTES")
    elif relatorio.score_risco < 10:
        print(f"Classificação: {Config.C_YEL}BAIXO RISCO (Indícios circunstanciais){Config.C_RST}")
    elif relatorio.score_risco < 20:
        print(f"Classificação: {Config.C_YEL}RISCO MODERADO (Anomalias detectadas){Config.C_RST}")
    else:
        print(f"Classificação: {Config.C_RED}ALTO RISCO (Assinaturas ou modificações críticas encontradas){Config.C_RST}")

def main():
    print(f"{Config.C_CYAN}>>> FORENSIC AUDIT TOOL - PRODUCTION READY <<<{Config.C_RST}")
    print("Nota: Este script realiza apenas leituras. Nenhuma alteração será feita.")
    
    # Detecção automática ou manual
    path_default = "/storage/emulated/0/"
    print(f"Diretório padrão: {path_default}")
    user_in = input("Pressione ENTER para usar o padrão ou digite o caminho: ").strip()
    
    path_target = user_in.replace('"', '').replace("'", "") if user_in else path_default
    
    if not os.path.exists(path_target):
        print(f"{Config.C_RED}ERRO: Diretório não encontrado.{Config.C_RST}")
        return

    # Inicia Auditoria
    audit = Relatorio(path_target)
    
    print("\nExecutando módulos de análise...")
    analisar_ambiente_permissivo(path_target, audit)
    analisar_estrutura_obb(path_target, audit)
    analisar_anomalia_shared_prefs(path_target, audit)
    analisar_residuos_gerais(path_target, audit)
    
    gerar_relatorio_final(audit)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperação cancelada pelo usuário.")
