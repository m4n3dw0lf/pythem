// Copyright (c) 2016 m4n3dw0lf
// 
// Jarvis is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation; either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
// USA

#define KEY_SLASH 0x51
#define KEY_SPACE 0X20

String option;
int i;

void tab(){
  Keyboard.press(KEY_TAB);
  Keyboard.releaseAll();
  delay(300);
}
  
void up(){
  Keyboard.press(KEY_UP_ARROW);
  Keyboard.releaseAll();
  delay(300);
}

void down(){
  Keyboard.press(KEY_DOWN_ARROW);
  Keyboard.releaseAll();
  delay(300);
}

void right(){
  Keyboard.press(KEY_RIGHT_ARROW);
  Keyboard.releaseAll();
  delay(300);
}
  
void left(){
  Keyboard.press(KEY_LEFT_ARROW);
  Keyboard.releaseAll();
  delay(300);
}

void super(){
  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.releaseAll();
  delay(300);
}

void slash(){
  Keyboard.press(KEY_RIGHT_ALT);
  Keyboard.press(KEY_SLASH);
  Keyboard.releaseAll();
  delay(300);
}

void backspace(){
  Keyboard.press(KEY_BACKSPACE);
  Keyboard.releaseAll();
  delay(300);
}

void erase(){
  Keyboard.press(KEY_BACKSPACE);
  Keyboard.releaseAll();
  delay(300);
  Keyboard.press(KEY_BACKSPACE);
  Keyboard.releaseAll();
  delay(300);
  Keyboard.press(KEY_BACKSPACE);
  Keyboard.releaseAll();
  delay(300);
  Keyboard.press(KEY_BACKSPACE);
  Keyboard.releaseAll();
  delay(300);
  Keyboard.press(KEY_BACKSPACE);
  Keyboard.releaseAll();
  delay(300);
  Keyboard.press(KEY_BACKSPACE);
  Keyboard.releaseAll();
  delay(300);
  Keyboard.press(KEY_BACKSPACE);
  Keyboard.releaseAll();
  delay(300);
  Keyboard.press(KEY_BACKSPACE);
  Keyboard.releaseAll();
  delay(300);
  Keyboard.press(KEY_BACKSPACE);
  Keyboard.releaseAll();
  delay(300);
  Keyboard.press(KEY_BACKSPACE);
  Keyboard.releaseAll();
  delay(300);
}

void escape(){
  Keyboard.press(KEY_ESC);
  Keyboard.releaseAll();
  delay(300);
}

void backtab(){
  Keyboard.press(KEY_LEFT_SHIFT);
  Keyboard.press(KEY_TAB);
  Keyboard.releaseAll();
  delay(300);
}

void space(){
  Keyboard.press(KEY_SPACE);
  Keyboard.releaseAll();
  delay(300);
}

void altf4(){
  Keyboard.press(KEY_LEFT_ALT);
  Keyboard.press(KEY_F4);
  Keyboard.releaseAll();
  delay(300);
}

void enter(){
  Keyboard.press(KEY_RETURN);
  Keyboard.releaseAll();
  delay(300);
}

void KeyboardPrint(String command){
  delay(300);
  Keyboard.begin();
  Keyboard.print(command);
  Keyboard.end();
  delay(300);
}

void altf2(String command){
  delay(300);
  Keyboard.press(KEY_LEFT_ALT);
  Keyboard.press(KEY_F2);
  Keyboard.releaseAll();
  delay(300);
  Keyboard.begin();
  Keyboard.print(command);
  Keyboard.end();
  Keyboard.press(KEY_RETURN);
  Keyboard.releaseAll();
}

void setup(){
  Serial.begin(9600);
}

void loop(){
  while (Serial.available()==0){}
  while (option != "quit"){
    option = Serial.readString();
    if (option == "status");{
      Serial.println("Jarvis");
    }
    if (option == "quit"){
      Serial.println("quit");
      break;
    }
    else if(option == "forward"){
      tab();
    }
    else if(option == "up"){
      up();
    }
    else if(option == "down"){
      down();
    }
    else if(option == "right"){
      right();
    }
    else if(option == "left"){
      left();
    }
    else if(option == "escape"){
      escape();
    }
    else if(option == "super"){
      super();
    }
    else if(option == "slash"){
      slash();
    }
    else if(option == "backspace"){
      backspace();
    }
    else if(option == "back"){
      backtab();
    }
    else if(option == "erase"){
      erase();
    }
    else if(option == "space"){
      space();
    }
    else if(option == "enter"){
      enter();
    }
    else if(option == "close"){
      altf4();
    }
    else if(option == "browser"){
      altf2("google-chrome");
    }
    else if(option == "terminal"){
      altf2("gnome-terminal");
    }
    else{
      KeyboardPrint(option);
    }
  }
 }
