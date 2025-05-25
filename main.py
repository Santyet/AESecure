from tkinterdnd2 import TkinterDnD
from gui import FileEncryptorApp

if __name__ == '__main__':
    root = TkinterDnD.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
