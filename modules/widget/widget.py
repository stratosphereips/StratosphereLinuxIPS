import tkinter as tk
import math
import webbrowser
import time

class FloatingWidget:
    def __init__(self, texts):
        self.window = tk.Toplevel()
        self.window.overrideredirect(True)
        self.window.geometry("+100+100")
        self.window.wm_attributes("-alpha", 0.8)
        self.window.attributes('-topmost', True)
        self.width = 200
        self.height = 200
        self.canvas = tk.Canvas(self.window, width=self.width, height=self.height, bd=0, highlightthickness=0)
        self.canvas.pack()
        self.create_sections(texts)
        self.create_link_circle('https://www.google.com/')

        self.canvas.bind("<ButtonPress-1>", self.start_move)
        self.canvas.bind("<B1-Motion>", self.on_move)
        self.canvas.bind("<ButtonRelease-1>", self.stop_move)
        self.canvas.bind("<ButtonPress-3>", self.start_resize)
        self.canvas.bind("<B3-Motion>", self.on_resize)
        self.canvas.bind("<ButtonRelease-3>", self.stop_resize)

    def create_sections(self, texts):
        colors = ['red', 'blue', 'green', 'orange']
        for i in range(4):
            start_angle = i * 90
            end_angle = (i+1) * 90
            color = colors[i]
            self.canvas.create_arc(0, 0, self.width, self.height, start=start_angle, extent=90, fill=color, outline=color)
            angle = math.radians(start_angle + 45)
            x = int(self.width/2 + self.width/3 * math.cos(angle))
            y = int(self.height/2 - self.height/3 * math.sin(angle))
            self.canvas.create_text(x, y, text=texts[i], fill='white', font=('Arial', 12, 'bold'))
    def create_link_circle(self, url):
        center_x = self.width//2
        center_y = self.height//2
        radius = self.width//6
        link_circle = self.canvas.create_oval(center_x-radius, center_y-radius, center_x+radius, center_y+radius, fill='white')
        self.canvas.tag_bind(link_circle, '<Button-1>', lambda event: self.open_website(url))
        self.canvas.create_text(center_x, center_y, text='Link', fill='black', font=('Arial', 10, 'bold'))

    def open_website(self, url):
        webbrowser.open_new(url)

    def start_move(self, event):
        self.x = event.x
        self.y = event.y

    def on_move(self, event):
        del_x = event.x - self.x
        del_y = event.y - self.y
        self.window.geometry(f"+{self.window.winfo_x()+del_x}+{self.window.winfo_y()+del_y}")

    def stop_move(self, event):
        pass

    def start_resize(self, event):
        self.width, self.height = self.window.winfo_width(), self.window.winfo_height()
        self.x, self.y = event.x, event.y

    def on_resize(self, event):
        del_x = event.x - self.x
        del_y = event.y - self.y
        self.width = max(50, self.width+2*del_x)
        self.height = max(50, self.height+2*del_y)
        self.canvas.config(width=self.width, height=self.height)

    def stop_resize(self, event):
        pass

    def hide_website(self):
        self.canvas.delete('link')

    def update_texts(self, new_texts):
        for i, text in enumerate(new_texts):
            angle = math.radians(i * 90 + 45)
            x = int(self.width/2 + self.width/3 * math.cos(angle))
            y = int(self.height/2 - self.height/3 * math.sin(angle))
            text_item = self.canvas.find_withtag(f'text_{i}')
            self.canvas.itemconfigure(text_item, text=text)
    
if __name__ == '__main__':
    texts = ['Hello', 'Hi', 'Here', 'There']
    fw = FloatingWidget(texts)
    fw.window.mainloop()
