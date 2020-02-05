//
// Created by ISU on 04/02/2020.
//

#include "gtest/gtest.h"

#include "CryptoBench/library.hpp"

class HelloWorldFixture : public ::testing::Test {


protected:
    virtual void TearDown()
    {
        std::cout << "Setup" << "\n";
    }

    virtual void SetUp()
    {

    }

};

TEST(HelloWorldFixture, Print)
{
    hello();
    ASSERT_TRUE(true);
}

