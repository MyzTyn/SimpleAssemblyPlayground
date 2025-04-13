//
//  Console.h
//  SimpleAssemblyPlayground
//
//  Created by MyzTyn on 2025/04/13.
//

#ifndef Console_h
#define Console_h

#include <string>

#include "imgui.h"

// Simple Console Window
struct Console {
    char InputBuf[256];
    ImVector<char *> Items;
    ImVector<const char *> Commands;
    ImVector<char *> History;
    int HistoryPos; // -1: new line, 0..History.Size-1 browsing history.
    ImGuiTextFilter Filter;
    bool AutoScroll;
    bool ScrollToBottom;

    static Console& Instance() {
        static Console instance;
        return instance;
    }

    Console();
    ~Console();

    // Portable helpers
    static int Stricmp(const char *s1, const char *s2) {
        int d;
        while ((d = toupper(*s2) - toupper(*s1)) == 0 && *s1) {
            s1++;
            s2++;
        }
        return d;
    }
    static int Strnicmp(const char *s1, const char *s2, int n) {
        int d = 0;
        while (n > 0 && (d = toupper(*s2) - toupper(*s1)) == 0 && *s1) {
            s1++;
            s2++;
            n--;
        }
        return d;
    }
    static char *Strdup(const char *s) {
        IM_ASSERT(s);
        const size_t len = strlen(s) + 1;
        void *buf = ImGui::MemAlloc(len);
        IM_ASSERT(buf);
        return static_cast<char *>(memcpy(buf, s, len));
    }
    static void Strtrim(char *s) {
        char *str_end = s + strlen(s);
        while (str_end > s && str_end[-1] == ' ')
            str_end--;
        *str_end = 0;
    }

    void ClearLog();

    void AddLog(const char *fmt, ...) IM_FMTARGS(2);

    void Draw(const char *title);

    void ExecCommand(const char *command_line);

    // In C++11 you'd be better off using lambdas for this sort of forwarding
    // callbacks
    static int TextEditCallbackStub(ImGuiInputTextCallbackData *data) {
        auto *console = static_cast<Console *>(data->UserData);
        return console->TextEditCallback(data);
    }

    int TextEditCallback(ImGuiInputTextCallbackData *data);
};

#endif
