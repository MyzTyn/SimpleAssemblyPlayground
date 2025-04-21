//
//  app.h
//  ia32_emulator
//
//  Created by MyzTyn on 2025/03/26.
//

#ifndef app_h
#define app_h

#include "imgui.h"

class Application {
public:
  Application();
  ~Application();

  void Render();
  ImVec4 &GetClearColor() { return clear_color_; }

private:
  ImGuiIO &io_;
  ImVec4 clear_color_ = ImVec4(0.45F, 0.55F, 0.60F, 1.00F);
};

#endif /* app_h */
