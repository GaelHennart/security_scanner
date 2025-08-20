import schedule
import time
import subprocess

def run_scans():
    print("Lancement des scans avec docker compose up")
    project_path = r"C:\Gael\ISEN\stage_a_etranger_M1\security_scanner"

    try:
        subprocess.run(["docker", "compose", "up", "--build"], cwd=project_path, check=True)
        print("Scans terminés")
    except subprocess.CalledProcessError as e:
        print(f"Erreur pendant l'exécution : {e}")

schedule.every(10).minutes.do(run_scans)

print("Lancement des scans toutes les 10 minutes")
run_scans()

while True:
    schedule.run_pending()
    time.sleep(1)
