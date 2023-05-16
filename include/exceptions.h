#pragma once

#ifndef INCLUDED_EXCEPTIONS_H
#define INCLUDED_EXCEPTIONS_H

#include <stdexcept>
#include <string>

class NotImplementedException : public std::logic_error
{
public:
  NotImplementedException(std::string messsage)
      : std::logic_error{messsage}
  {
  }
};

class InvalidValueError : public std::invalid_argument
{
public:
  InvalidValueError(std::string messsage)
      : std::invalid_argument{messsage}
  {
  }
};

class InvalidHrzrHeader : public std::invalid_argument
{
public:
  InvalidHrzrHeader(std::string messsage)
      : std::invalid_argument{messsage}
  {
  }
};

#endif // INCLUDED_EXCEPTIONS_H
