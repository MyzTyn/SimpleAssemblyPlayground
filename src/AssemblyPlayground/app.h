//
//  app.h
//  ia32_emulator
//
//  Created by MyzTyn on 2025/03/26.
//

#ifndef app_h
#define app_h

#include <stdio.h>
#include "imgui.h"

class Application {
public:
    Application();
    ~Application();
    
    void Render();
    ImVec4& GetClearColor() {
        return clear_color;
    }
private:
    ImGuiIO& io;
    ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);
};

#endif /* app_h */
