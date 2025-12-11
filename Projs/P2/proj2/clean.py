import shutil
import os

def remover_pastas(lista_caminhos: list, forcar_remocao: bool = False) -> dict:
    """
    Remove pastas específicas e retorna um relatório da operação.

    Args:
        lista_caminhos (list): Lista de caminhos absolutos das pastas a remover
        forcar_remocao (bool): Ignora confirmação manual (default: False)

    Returns:
        dict: Relatório com sucessos, falhas e totais
    """
    relatorio = {
        'sucesso': [],
        'falhas': {},
        'total_pastas': len(lista_caminhos),
        'removidas': 0
    }

    for caminho in lista_caminhos:
        try:
            if not os.path.exists(caminho):
                raise FileNotFoundError(f"O caminho {caminho} não existe")

            if not forcar_remocao:
                confirmacao = input(f"Remover a pasta {caminho}? [s/N]: ")
                if confirmacao.lower() != 's':
                    continue

            # Verifica se é uma pasta válida
            if os.path.isdir(caminho):
                shutil.rmtree(caminho)
                relatorio['sucesso'].append(caminho)
                relatorio['removidas'] += 1
                print(f"Pasta removida: {caminho}")
            else:
                raise NotADirectoryError(f"{caminho} não é uma pasta válida")

        except Exception as e:
            relatorio['falhas'][caminho] = str(e)
            print(f"Erro ao remover {caminho}: {str(e)}")

    return relatorio


pastas_para_remover_joao = [
    '/Users/35193/Documents/GitHub/ES-CSI/2425-G8/Projs/proj2_joao/proj2/WebAPI/__pycache__',
    '/Users/35193/Documents/GitHub/ES-CSI/2425-G8/Projs/proj2_joao/proj2/WebAPI/DB',
    '/Users/35193/Documents/GitHub/ES-CSI/2425-G8/Projs/proj2_joao/proj2/Client/DB_USERS',
    '/Users/35193/Documents/GitHub/ES-CSI/2425-G8/Projs/proj2_joao/proj2/Client/.tokens'
]

pasta_para_remover_martim = [
    '/mnt/c/Users/MSI/Desktop/Uni/CSI/ES/proj2/Client/__pycache__',
    '/mnt/c/Users/MSI/Desktop/Uni/CSI/ES/proj2/Client/.tokens',
    '/mnt/c/Users/MSI/Desktop/Uni/CSI/ES/proj2/Client/DB_USERS',
    '/mnt/c/Users/MSI/Desktop/Uni/CSI/ES/proj2/P1/__pycache__',
    '/mnt/c/Users/MSI/Desktop/Uni/CSI/ES/proj2/WebAPI/__pycache__',
    '/mnt/c/Users/MSI/Desktop/Uni/CSI/ES/proj2/WebAPI/DB'
]

pastas_para_remover = pasta_para_remover_martim
# pastas_para_remover = pastas_para_remover_joao

resultado = remover_pastas(pastas_para_remover)
print("\nRelatório final:")
print(f"Pastas removidas com sucesso: {resultado['removidas']}")
print(f"Falhas: {len(resultado['falhas'])}")