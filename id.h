#ifndef ID_H
#define ID_H
#include "stdafx.h"

class ID
{
private:
    uint8_t id[6];
public:
    ID(uint8_t* id);
    bool operator<(const ID& other) const;
    bool operator==(const ID &other) const;

    uint8_t* getID();
};

#endif // ID_H
