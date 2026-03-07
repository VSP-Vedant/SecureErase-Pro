"""
SecureErase Pro — Desktop Application Entry Point
Launches the UIController and initializes all modules.
"""
import sys
from modules.ui_controller import UIController
from PyQt6.QtWidgets import QApplication

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("SecureErase Pro")
    app.setApplicationVersion("0.1.0")
    window = UIController()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
