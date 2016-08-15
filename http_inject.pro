TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c \
    pkcntl.c

LIBS += -lpcap

HEADERS += \
    pkcntl.h
