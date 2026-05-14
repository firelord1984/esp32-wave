#pragma once
#include <Arduino.h>
#include "config.h"

void menuInit();
void menuTick();   // call every loop()
void printBanner();
void printHelp();
