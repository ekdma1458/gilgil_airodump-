#include "id.h"

ID::ID(uint8_t *id)
{
    memcpy(this->id, id, 6);
}
bool ID::operator<(const ID &other) const{
    return memcmp(this->id, &other, 6) < 0;
}
bool ID::operator==(const ID &other) const{
    return memcmp(this->id, &other, 6) == 0;
}
uint8_t* ID::getID(){
    return this->id;
}
