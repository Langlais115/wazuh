#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <sca_policy.hpp>
#include <sca_policy_loader.hpp>
#include <sca_policy_parser.hpp>
#include <yaml_document.hpp>

#include "logging_helper.hpp"

#include <mock_dbsync.hpp>
#include <mock_filesystem_wrapper.hpp>

#include <memory>

class ScaPolicyLoaderTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Set up the logging callback to avoid "Log callback not set" errors
        LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* /* log */) {
            // Mock logging callback that does nothing
        });

    }
};

TEST_F(ScaPolicyLoaderTest, ConstructionNoPolicies)
{
    auto fsMock = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();
    const SCAPolicyLoader loader({}, fsMock);
    SUCCEED();
}

TEST_F(ScaPolicyLoaderTest, ConstructionSomePolicies)
{
    auto fsMock = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();

    std::vector<sca::PolicyData> policies { {"dummy/path/1", true, false},
        {"dummy/path/2", true, false},
        {"dummy/path/3", true, false},
        {"dummy/path/4", false, false}};

    const SCAPolicyLoader loader(policies, fsMock);
    SUCCEED();
}

TEST_F(ScaPolicyLoaderTest, LoadPoliciesNoPolicies)
{
    auto fsMock = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();
    auto dbSync = std::make_shared<MockDBSync>();

    const SCAPolicyLoader loader({}, fsMock, dbSync);
    ASSERT_EQ(loader.LoadPolicies(30, true, [](auto, auto) { return; }).size(), 0);
}

TEST_F(ScaPolicyLoaderTest, LoadPoliciesSomePolicies)
{
    auto fsMock = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();
    MockFileSystemWrapper* m_rawFsMock = fsMock.get();

    EXPECT_CALL(*m_rawFsMock, exists(::testing::_))
    .Times(::testing::AnyNumber())
    .WillRepeatedly([](const std::filesystem::path & p)
    {
        return true;
    });

    auto dbSync = std::make_shared<MockDBSync>();

    std::vector<sca::PolicyData> policies { {"dummy/path/1", true, false},
        {"dummy/path/2", true, false},
        {"dummy/path/3", true, false},
        {"dummy/path/4", false, false}};

    const SCAPolicyLoader loader(policies, fsMock, dbSync);
    ASSERT_EQ(loader.LoadPolicies(30, true, [](auto, auto)
    {
        return;
    }).size(), 0);
}

TEST_F(ScaPolicyLoaderTest, SyncPoliciesAndReportDeltaBadData)
{
    auto fsMock = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();
    auto dbSync = std::make_shared<MockDBSync>();

    MockFileSystemWrapper* m_rawFsMock = fsMock.get();

    EXPECT_CALL(*m_rawFsMock, exists(::testing::_))
    .Times(::testing::AnyNumber())
    .WillRepeatedly([](const std::filesystem::path & p)
    {
        return true;
    });

    const std::string yml = R"(
      novariables:
        $var1: /etc
        $var11: /usr
      nopolicy:
        id: policy1
      nochecks:
        - id: check1
          title: "title"
          condition: "all"
          rules:
            - 'f: $var1/passwd exists'
            - 'f: $var11/shared exists'
      )";

    // create a yaml doc just to pass to the parser
    auto yamlDocument = std::make_unique<YamlDocument>(yml);
    const std::filesystem::path path("dummy.yaml");
    PolicyParser parser(path, 30, false, std::move(yamlDocument));

    // parse this policy and get a real policy object
    nlohmann::json jasonData;
    const auto policyOpt = parser.ParsePolicy(jasonData);
    ASSERT_FALSE(policyOpt);

    const SCAPolicyLoader loader({}, fsMock, dbSync);

    loader.SyncPoliciesAndReportDelta(jasonData, [](auto, auto)
    {
        return;
    });
    SUCCEED();
}


TEST_F(ScaPolicyLoaderTest, SyncPoliciesAndReportDeltaNoDBSyncObject)
{
    auto fsMock = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();
    auto dbSync = std::make_shared<MockDBSync>();

    MockFileSystemWrapper* m_rawFsMock = fsMock.get();

    EXPECT_CALL(*m_rawFsMock, exists(::testing::_))
    .Times(::testing::AnyNumber())
    .WillRepeatedly([](const std::filesystem::path & p)
    {
        return true;
    });

    const std::string yml = R"(
      variables:
        $var1: /etc
        $var11: /usr
      policy:
        id: policy1
      checks:
        - id: check1
          title: "title"
          condition: "all"
          rules:
            - 'f: $var1/passwd exists'
            - 'f: $var11/shared exists'
      )";

    // create a yaml doc just to pass to the parser
    auto yamlDocument = std::make_unique<YamlDocument>(yml);
    const std::filesystem::path path("dummy.yaml");
    PolicyParser parser(path, 30, false, std::move(yamlDocument));

    // parse this policy and get a real policy object
    nlohmann::json jasonData;
    const auto policyOpt = parser.ParsePolicy(jasonData);
    ASSERT_TRUE(policyOpt);

    const SCAPolicyLoader loader({}, fsMock, nullptr);

    loader.SyncPoliciesAndReportDelta(jasonData, [](auto, auto)
    {
        return;
    });
    SUCCEED();
}


TEST_F(ScaPolicyLoaderTest, SyncPoliciesAndReportDelta)
{
    auto fsMock = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();
    auto dbSync = std::make_shared<MockDBSync>();

    MockFileSystemWrapper* rawFsMock = fsMock.get();
    MockDBSync* rawDbSyncMock = dbSync.get();

    EXPECT_CALL(*rawFsMock, exists(::testing::_))
    .Times(::testing::AnyNumber())
    .WillRepeatedly([](const std::filesystem::path & p)
    {
        return true;
    });

    EXPECT_CALL(*rawDbSyncMock, handle())
    .Times(::testing::AnyNumber())
    .WillRepeatedly([]()-> void*
    {
        return nullptr;
    });


    const std::string yml = R"(
      variables:
        $var1: /etc
        $var11: /usr
      policy:
        id: policy1
      checks:
        - id: check1
          title: "title"
          condition: "all"
          rules:
            - 'f: $var1/passwd exists'
            - 'f: $var11/shared exists'
      )";

    // create a yaml doc just to pass to the parser
    auto yamlDocument = std::make_unique<YamlDocument>(yml);
    const std::filesystem::path path("dummy.yaml");
    PolicyParser parser(path, 30, false, std::move(yamlDocument));

    // parse this policy and get a real policy object
    nlohmann::json jasonData;
    const auto policyOpt = parser.ParsePolicy(jasonData);
    ASSERT_TRUE(policyOpt);

    const SCAPolicyLoader loader({}, fsMock, dbSync);

    loader.SyncPoliciesAndReportDelta(jasonData, [](auto, auto)
    {
        return;
    });
    SUCCEED();
}
