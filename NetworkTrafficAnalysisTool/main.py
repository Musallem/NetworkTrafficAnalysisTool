import customtkinter

customtkinter.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"

class main(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        # Window Configuration
        self.title("NTAT - Network Traffic Analysis Tool")
        self.geometry(f"{650}x{580}")
        self.minsize(650, 580)

        # Grid Layout (4x4)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((2, 3), weight=0) # type: ignore        
        self.grid_rowconfigure((0, 1, 2), weight=1) # type: ignore        

        # Sidebar Frame 
        self.sidebar_frame = customtkinter.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)
        self.sidebar_frame.configure(fg_color=("#4B577E", "#4B577E"))
        self.logo_label = customtkinter.CTkLabel(self.sidebar_frame, text="[ NTAT ]",
              text_color="orange", font=customtkinter.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(100, 10))
        self.appearance_mode_label = customtkinter.CTkLabel(self.sidebar_frame, text="Appearance & Scaling:", anchor="w")
        self.appearance_mode_label.grid(row=5, column=0, padx=10, pady=(0, 0))
        self.appearance_mode_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame, hover = False,
            fg_color="#1E2742", button_color="#1E2742",values=["Light", "Dark", "System"],
            command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.grid(row=6, column=0, padx=10, pady=(10, 10))
        self.scaling_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame, hover = False,
            fg_color="#1E2742", button_color="#1E2742", values=["80%", "90%", "100%", "110%", "120%"],
            command=self.change_scaling_event)
        self.scaling_optionemenu.grid(row=8, column=0, padx=10, pady=(10, 20))

        # HOME LABEL AND BUTTONS
        self.label = customtkinter.CTkLabel(self, text="Traffic Application Classification | Covert Channel Detection", font=customtkinter.CTkFont(size=14, weight="bold"))
        self.label.grid(row=0, column=1, columnspan=4, padx=(20, 20), pady=(20, 170), sticky="nsew")
        self.main_button_1 = customtkinter.CTkButton(self, fg_color="transparent", text="Import pcap file", text_color=("gray10", "#DCE4EE"))
        self.main_button_1.grid(row=3, column=3, padx=(20, 20), pady=(20, 20), sticky="nsew")
        self.button_1 = customtkinter.CTkButton(self, text="Live Capture - Real-time Traffic Analysis", fg_color="#4B577E")
        self.button_1.grid(row=0, column=1, columnspan=3, padx=(20, 20), pady=(50, 10), sticky="ew")
        self.button_3 = customtkinter.CTkButton(self, text="Network Map - Show the Devices Connected to the Network", fg_color="#4B577E")
        self.button_3.grid(row=0, column=1, columnspan=3, padx=(20, 20), pady=(200, 10), sticky="ew")
        self.button_4 = customtkinter.CTkButton(self, text="DETECT COVERT CHANNELS", fg_color="#4B577E")
        self.button_4.grid(row=0, column=1, columnspan=3, padx=(20, 20), pady=(300, 10), sticky="ew")

        # Progressbar for LIVE CAPTURE
        self.slider_progressbar_frame = customtkinter.CTkFrame(self, fg_color="transparent")
        self.slider_progressbar_frame.grid(row=1, column=1, columnspan=3, padx=(20, 0), pady=(20, 0), sticky="nsew")
        self.slider_progressbar_frame.grid_columnconfigure(0, weight=1)
        self.slider_progressbar_frame.grid_rowconfigure(4, weight=1)
        self.progressbar_1 = customtkinter.CTkProgressBar(self.slider_progressbar_frame)
        self.progressbar_1.grid(row=1, column=0, padx=(20, 10), pady=(10, 10), sticky="nsew")

        #  default values
        self.appearance_mode_optionemenu.set("Dark")
        self.scaling_optionemenu.set("100%")
        self.progressbar_1.configure(mode="determinnate")
        self.progressbar_1.stop()

    def open_input_dialog_event(self):
        dialog = customtkinter.CTkInputDialog(text="Type in a number:", title="CTkInputDialog")
        print("CTkInputDialog:", dialog.get_input())

    def change_appearance_mode_event(self, new_appearance_mode: str):
        customtkinter.set_appearance_mode(new_appearance_mode)

    def change_scaling_event(self, new_scaling: str):
        new_scaling_float = int(new_scaling.replace("%", "")) / 100
        customtkinter.set_widget_scaling(new_scaling_float)

    def sidebar_button_event(self):
        print("sidebar_button click")

if __name__ == "__main__":
    Main = main()
    Main.mainloop()