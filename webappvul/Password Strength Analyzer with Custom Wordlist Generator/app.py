import argparse
import datetime
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from zxcvbn import zxcvbn
from itertools import product, permutations

class PasswordTool:
    def __init__(self):
        self.leet_map = {
            'a': ['@', '4'], 'e': ['3'], 'i': ['1', '!'], 
            'o': ['0'], 's': ['$', '5'], 't': ['7'], 'z': ['2']
        }
        self.special_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '?', '.']
        self.common_numbers = [str(i) for i in range(0, 100)] + [
            '111', '123', '1234', '12345', '123456', '000', '1111', '2222', 
            '100', '200', '99', '007', '123456789', '654321'
        ]

    def analyze_password(self, password):
        """Analyze password strength using zxcvbn"""
        result = zxcvbn(password)
        return {
            'score': result['score'],
            'feedback': result['feedback']['warning'] or "No major issues",
            'crack_time': result['crack_times_display']['offline_slow_hashing_1e4_per_second'],
            'guesses_log10': result['guesses_log10']
        }

    def generate_wordlist(self, base_words, output_file, years=None, 
                         leet_level=1, specials=True, numbers_mode='years',
                         min_length=4, max_length=30):
        """Generate custom wordlist based on user inputs"""
        # Process base words
        words = set()
        for word in base_words:
            if word:
                words.add(word.lower())
                words.add(word.capitalize())
        
        # Add combinations
        if len(base_words) > 1:
            for perm in permutations(base_words, 2):
                base_combo = ''.join(perm)
                words.add(base_combo.lower())
                words.add(base_combo.capitalize())
                
                for sep in ['', '_', '.', '-']:
                    sep_combo = sep.join(perm)
                    words.add(sep_combo.lower())
                    words.add(sep_combo.capitalize())
        
        # Apply leetspeak transformations
        all_words = set(words)
        if leet_level > 0:
            for word in words:
                self._apply_leet(all_words, word, leet_level)
        
        # Generate number suffixes
        suffixes = set()
        if numbers_mode in ['years', 'both']:
            current_year = datetime.datetime.now().year
            start_year = years[0] if years else 1900
            end_year = years[1] if years else current_year + 5
            for year in range(start_year, end_year + 1):
                suffixes.add(str(year))
                suffixes.add(str(year)[2:])  # Last two digits
        
        if numbers_mode in ['common', 'both']:
            suffixes.update(self.common_numbers)
        
        # Generate final wordlist
        results = set()
        for word in all_words:
            if min_length <= len(word) <= max_length:
                results.add(word)
            
            if specials:
                for char in self.special_chars:
                    new_word = word + char
                    if min_length <= len(new_word) <= max_length:
                        results.add(new_word)
            
            for suffix in suffixes:
                new_word = word + suffix
                if min_length <= len(new_word) <= max_length:
                    results.add(new_word)
                
                if specials:
                    for char in self.special_chars:
                        combo = new_word + char
                        if min_length <= len(combo) <= max_length:
                            results.add(combo)
        
        # Write to file
        with open(output_file, 'w') as f:
            for word in results:
                f.write(word + '\n')
        
        return len(results)

    def _apply_leet(self, word_set, word, level):
        """Apply leetspeak transformations to words"""
        if level >= 1:
            for i, char in enumerate(word):
                if char.lower() in self.leet_map:
                    for sub in self.leet_map[char.lower()]:
                        new_word = word[:i] + sub + word[i+1:]
                        word_set.add(new_word)
        
        if level >= 2:
            for indices in product(range(len(word)), repeat=2):
                if indices[0] >= indices[1]:
                    continue
                new_word = list(word)
                changes = 0
                for i in indices:
                    if word[i].lower() in self.leet_map:
                        new_word[i] = self.leet_map[word[i].lower()][0]
                        changes += 1
                if changes == 2:
                    word_set.add(''.join(new_word))

class PasswordToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Toolkit")
        self.tool = PasswordTool()
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Analysis Tab
        self.analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.analysis_frame, text='Password Analysis')
        self._setup_analysis_tab()
        
        # Generation Tab
        self.generation_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.generation_frame, text='Wordlist Generator')
        self._setup_generation_tab()

    def _setup_analysis_tab(self):
        # Password entry
        ttk.Label(self.analysis_frame, text="Password:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.password_entry = ttk.Entry(self.analysis_frame, width=40, show="*")
        self.password_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Show password checkbox
        self.show_pass = tk.BooleanVar()
        ttk.Checkbutton(
            self.analysis_frame, text="Show Password", 
            variable=self.show_pass, command=self.toggle_password
        ).grid(row=0, column=2, padx=5, pady=5)
        
        # Analyze button
        ttk.Button(
            self.analysis_frame, text="Analyze Password", 
            command=self.analyze_password
        ).grid(row=1, column=0, columnspan=3, pady=10)
        
        # Results display
        self.results_text = scrolledtext.ScrolledText(
            self.analysis_frame, width=50, height=10, state='disabled'
        )
        self.results_text.grid(row=2, column=0, columnspan=3, padx=5, pady=5)

    def _setup_generation_tab(self):
        # Personal info fields
        fields = [
            ("First Name:", "first_name"),
            ("Last Name:", "last_name"),
            ("Pet's Name:", "pet_name"),
            ("Birth Year:", "birth_year"),
            ("Partner's Name:", "partner_name"),
            ("Child's Name:", "child_name")
        ]
        
        self.entries = {}
        for i, (label, name) in enumerate(fields):
            ttk.Label(self.generation_frame, text=label).grid(row=i, column=0, padx=5, pady=5, sticky='w')
            self.entries[name] = ttk.Entry(self.generation_frame, width=25)
            self.entries[name].grid(row=i, column=1, padx=5, pady=5)
        
        # Options frame
        options_frame = ttk.LabelFrame(self.generation_frame, text="Generation Options")
        options_frame.grid(row=0, column=2, rowspan=6, padx=10, pady=5, sticky='n')
        
        # Leetspeak level
        ttk.Label(options_frame, text="Leetspeak Level:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.leet_level = tk.IntVar(value=1)
        ttk.Combobox(
            options_frame, textvariable=self.leet_level, 
            values=[0, 1, 2], width=3, state='readonly'
        ).grid(row=0, column=1, padx=5, pady=2)
        
        # Special characters
        self.specials = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_frame, text="Add Special Characters", 
            variable=self.specials
        ).grid(row=1, column=0, columnspan=2, padx=5, pady=2, sticky='w')
        
        # Numbers mode
        ttk.Label(options_frame, text="Number Suffixes:").grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.numbers_mode = tk.StringVar(value='years')
        ttk.Combobox(
            options_frame, textvariable=self.numbers_mode, 
            values=['years', 'common', 'both', 'none'], width=8
        ).grid(row=2, column=1, padx=5, pady=2)
        
        # Year range
        ttk.Label(options_frame, text="Year Range:").grid(row=3, column=0, padx=5, pady=2, sticky='w')
        self.year_start = ttk.Entry(options_frame, width=6)
        self.year_start.insert(0, "1950")
        self.year_start.grid(row=3, column=1, padx=5, pady=2)
        ttk.Label(options_frame, text="to").grid(row=3, column=2, padx=2, pady=2)
        self.year_end = ttk.Entry(options_frame, width=6)
        current_year = datetime.datetime.now().year
        self.year_end.insert(0, str(current_year + 5))
        self.year_end.grid(row=3, column=3, padx=5, pady=2)
        
        # Length constraints
        ttk.Label(options_frame, text="Min Length:").grid(row=4, column=0, padx=5, pady=2, sticky='w')
        self.min_length = ttk.Entry(options_frame, width=6)
        self.min_length.insert(0, "4")
        self.min_length.grid(row=4, column=1, padx=5, pady=2)
        
        ttk.Label(options_frame, text="Max Length:").grid(row=4, column=2, padx=5, pady=2, sticky='w')
        self.max_length = ttk.Entry(options_frame, width=6)
        self.max_length.insert(0, "30")
        self.max_length.grid(row=4, column=3, padx=5, pady=2)
        
        # Generate button
        ttk.Button(
            self.generation_frame, text="Generate Wordlist", 
            command=self.generate_wordlist
        ).grid(row=6, column=0, columnspan=3, pady=10)
        
        # Status label
        self.status = ttk.Label(self.generation_frame, text="")
        self.status.grid(row=7, column=0, columnspan=3, pady=5)

    def toggle_password(self):
        """Toggle password visibility"""
        show = self.show_pass.get()
        self.password_entry.config(show="" if show else "*")

    def analyze_password(self):
        """Handle password analysis"""
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Input Error", "Please enter a password to analyze")
            return
        
        result = self.tool.analyze_password(password)
        
        # Display results
        self.results_text.config(state='normal')
        self.results_text.delete(1.0, tk.END)
        
        strength = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
        self.results_text.insert(tk.END, f"Password Strength: {strength[result['score']]}\n")
        self.results_text.insert(tk.END, f"Score: {result['score']}/4\n")
        self.results_text.insert(tk.END, f"Estimated Crack Time: {result['crack_time']}\n")
        self.results_text.insert(tk.END, f"Guesses (log10): {result['guesses_log10']}\n")
        self.results_text.insert(tk.END, f"Feedback: {result['feedback']}")
        
        self.results_text.config(state='disabled')

    def generate_wordlist(self):
        """Handle wordlist generation"""
        # Collect base words
        base_words = [
            self.entries['first_name'].get(),
            self.entries['last_name'].get(),
            self.entries['pet_name'].get(),
            self.entries['birth_year'].get(),
            self.entries['partner_name'].get(),
            self.entries['child_name'].get()
        ]
        
        # Filter out empty fields
        base_words = [word for word in base_words if word.strip()]
        
        if not base_words:
            messagebox.showwarning("Input Error", "Please provide at least one personal detail")
            return
        
        # Get output file
        output_file = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not output_file:
            return
        
        # Get options
        try:
            leet_level = self.leet_level.get()
            specials = self.specials.get()
            numbers_mode = self.numbers_mode.get()
            min_length = int(self.min_length.get())
            max_length = int(self.max_length.get())
            
            years = None
            if numbers_mode in ['years', 'both']:
                years = (
                    int(self.year_start.get()),
                    int(self.year_end.get())
                )
        except ValueError as e:
            messagebox.showerror("Input Error", f"Invalid number input: {str(e)}")
            return
        
        # Generate wordlist
        try:
            word_count = self.tool.generate_wordlist(
                base_words, output_file, years, leet_level, 
                specials, numbers_mode, min_length, max_length
            )
            self.status.config(text=f"Generated {word_count} words to {output_file}")
        except Exception as e:
            messagebox.showerror("Generation Error", str(e))

def main():
    parser = argparse.ArgumentParser(description='Password Strength Analyzer and Wordlist Generator')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analysis command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze password strength')
    analyze_parser.add_argument('password', help='Password to analyze')
    
    # Generate command
    generate_parser = subparsers.add_parser('generate', help='Generate custom wordlist')
    generate_parser.add_argument('-o', '--output', required=True, help='Output file name')
    generate_parser.add_argument('--words', nargs='+', required=True, help='Base words for wordlist')
    generate_parser.add_argument('--leet', type=int, default=1, choices=[0,1,2], help='Leetspeak level (0-2)')
    generate_parser.add_argument('--specials', action='store_true', help='Add special characters')
    generate_parser.add_argument('--numbers', choices=['years', 'common', 'both', 'none'], default='years', 
                                help='Number suffix mode')
    generate_parser.add_argument('--start-year', type=int, default=1900, help='Start year for suffixes')
    generate_parser.add_argument('--end-year', type=int, default=None, help='End year for suffixes')
    generate_parser.add_argument('--min-len', type=int, default=4, help='Minimum password length')
    generate_parser.add_argument('--max-len', type=int, default=30, help='Maximum password length')
    
    args = parser.parse_args()
    tool = PasswordTool()
    
    if args.command == 'analyze':
        result = tool.analyze_password(args.password)
        print(f"Password Strength: {result['score']}/4")
        print(f"Feedback: {result['feedback']}")
        print(f"Crack Time: {result['crack_time']}")
        print(f"Guesses (log10): {result['guesses_log10']}")
    
    elif args.command == 'generate':
        if args.end_year is None:
            args.end_year = datetime.datetime.now().year + 5
        count = tool.generate_wordlist(
            args.words, args.output, 
            (args.start_year, args.end_year), args.leet, 
            args.specials, args.numbers, args.min_len, args.max_len
        )
        print(f"Generated {count} words to {args.output}")
    
    else:
        # Start GUI if no command provided
        root = tk.Tk()
        app = PasswordToolGUI(root)
        root.mainloop()

if __name__ == "__main__":
    main()