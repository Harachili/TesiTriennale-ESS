# Condivisione di Segreti Dinamica: Un'Implementazione

Questo repository contiene la relazione finale e le implementazioni di algoritmi sviluppati per la mia tesi triennale sul tema del Secret Sharing e dell'Evolving Secret Sharing.

## Contenuto del Repository

- **`tesiDanellaFinale.pdf`**: La versione finale della tesi, che esplora in dettaglio i concetti di Secret Sharing ed Evolving Secret Sharing, insieme alle implementazioni sviluppate.
- **`slideFinaliDanella.pdf`**: Le slide utilizzate per la presentazione della tesi, che forniscono una panoramica dei punti chiave trattati.
- **`shamirScheme.py`**: Uno script Python che implementa lo schema di Shamir per la condivisione di segreti, un metodo classico per dividere un segreto in parti che possono essere ricombinate per ricostruire il segreto originale.
- **`evolvingSS.py`**: Uno script Python che implementa l'Evolving Secret Sharing, un'estensione dinamica dello schema di Shamir che permette di aggiornare le condivisioni senza dover rigenerare l'intero segreto.

## Requisiti

Le implementazioni sono scritte in Python e richiedono l'installazione di librerie specifiche. 
Si consiglia di consultare i singoli script per dettagli sui requisiti e sulle dipendenze necessarie.

## Esecuzione degli Script

Per eseguire gli script Python:
  - Assicurarsi di avere Python con le librerie numpy, sympy e random installati
  - Eseguire gli script tramite la riga di comando:

   ```bash
   python nome_script.py
   ```

   Sostituire `nome_script.py` con `shamirScheme.py` o `evolvingSS.py` a seconda dell'implementazione desiderata.
