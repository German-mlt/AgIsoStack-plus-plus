//================================================================================================
/// @file vt_parse_policy_tests.cpp
///
/// @brief Unit tests for the strict and tolerant object pool parse policies
///
/// @copyright 2026 The Open-Agriculture Developers
//================================================================================================
#include <gtest/gtest.h>

#include "isobus/isobus/isobus_virtual_terminal_server_managed_working_set.hpp"

#include <vector>

using namespace isobus;
using Policy = VirtualTerminalWorkingSetBase::ParsePolicy;
using Bytes = std::vector<std::uint8_t>;

namespace
{
	void append(Bytes &pool, const Bytes &object)
	{
		pool.insert(pool.end(), object.begin(), object.end());
	}

	Bytes working_set(std::uint16_t id = 0)
	{
		return { static_cast<std::uint8_t>(id & 0xFF), static_cast<std::uint8_t>(id >> 8), 0, 0, 1, 0xE8, 0x03, 0, 0, 0 };
	}

	// A valid fill attributes object, used to prove parsing continues after an accepted issue.
	Bytes sentinel(std::uint16_t id)
	{
		return { static_cast<std::uint8_t>(id & 0xFF), static_cast<std::uint8_t>(id >> 8), 25, 2, 4, 0xFF, 0xFF, 0 };
	}

	// Objects with an invalid value inside, each one with a known length.
	const Bytes alarmMaskPriority{ 0x64, 0x00, 2, 1, 0xFF, 0xFF, 7, 9, 0, 0 }; // id 100
	const Bytes fillType{ 0x65, 0x00, 25, 9, 4, 0xFF, 0xFF, 0 }; // id 101
	const Bytes fontType{ 0x66, 0x00, 23, 1, 2, 0xF5, 0, 0 }; // id 102, proprietary type 245
	const Bytes ellipseType{ 0x67, 0x00, 15, 0xFF, 0xFF, 10, 0, 10, 0, 9, 0, 0, 0xFF, 0xFF, 0 }; // id 103
	const Bytes polygonType{ 0x68, 0x00, 16, 10, 0, 10, 0, 0xFF, 0xFF, 0xFF, 0xFF, 8, 3, 0, 0, 0, 0, 0, 10, 0, 0, 0, 10, 0, 10, 0 }; // id 104
	const Bytes colourMapCount{ 0x69, 0x00, 39, 3, 0, 1, 2, 3 }; // id 105, 3 indexes
	const Bytes macroCommand{ 0x6A, 0x00, 28, 8, 0, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }; // id 106
	const Bytes pictureFormat{ 0x6B, 0x00, 20, 2, 0, 2, 0, 2, 0, 7, 0, 0, 4, 0, 0, 0, 0, 1, 2, 3, 4 }; // id 107
	const Bytes keyGroupKeys{ 0x6C, 0x00, 35, 0, 0xFF, 0xFF, 0xFF, 0xFF, 5, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 0 }; // id 108
	const Bytes windowMaskType{ 0x6D, 0x00, 34, 1, 1, 30, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0 }; // id 109
	const Bytes macroEvent{ 0x6E, 0x00, 25, 2, 4, 0xFF, 0xFF, 1, 0, 0x6A }; // id 110, reserved event 0

	std::vector<Bytes> invalid_objects()
	{
		return { alarmMaskPriority, fillType, fontType, ellipseType, polygonType, colourMapCount,
			       macroCommand, pictureFormat, keyGroupKeys, windowMaskType, macroEvent };
	}

	bool parse(VirtualTerminalServerManagedWorkingSet &workingSet, Bytes pool)
	{
		return workingSet.parse_iop_into_objects(pool.data(), static_cast<std::uint32_t>(pool.size()));
	}
} // namespace

TEST(VT_PARSE_POLICY_TESTS, StrictIsTheDefaultAndRejectsEachInvalidValue)
{
	for (const auto &object : invalid_objects())
	{
		VirtualTerminalServerManagedWorkingSet workingSet;
		EXPECT_EQ(Policy::Strict, workingSet.get_parse_policy());
		Bytes pool = working_set();
		append(pool, object);
		append(pool, sentinel(500));
		EXPECT_FALSE(parse(workingSet, pool)) << "object " << static_cast<int>(object[0]);
		EXPECT_TRUE(workingSet.get_parse_issues().empty());
	}
}

TEST(VT_PARSE_POLICY_TESTS, TolerantAcceptsAndRecordsEachInvalidValue)
{
	VirtualTerminalServerManagedWorkingSet workingSet;
	workingSet.set_parse_policy(Policy::Tolerant);
	Bytes pool = working_set();
	for (const auto &object : invalid_objects())
	{
		append(pool, object);
	}
	append(pool, sentinel(500));
	ASSERT_TRUE(parse(workingSet, pool));

	// Parsing continued past every issue, up to the last object.
	ASSERT_NE(nullptr, workingSet.get_object_by_id(500));

	const auto issues = workingSet.get_parse_issues();
	// Alarm mask: priority and acoustic signal; the others one each.
	ASSERT_EQ(12U, issues.size());
	std::vector<std::uint16_t> ids;
	for (const auto &issue : issues)
	{
		ids.push_back(issue.objectID);
		EXPECT_FALSE(issue.description.empty());
	}
	EXPECT_EQ((std::vector<std::uint16_t>{ 100, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110 }), ids);

	auto alarm = std::static_pointer_cast<AlarmMask>(workingSet.get_object_by_id(100));
	ASSERT_NE(nullptr, alarm);
	EXPECT_EQ(AlarmMask::Priority::High, alarm->get_mask_priority());
	EXPECT_EQ(AlarmMask::AcousticSignal::Highest, alarm->get_signal_priority());

	auto fill = std::static_pointer_cast<FillAttributes>(workingSet.get_object_by_id(101));
	ASSERT_NE(nullptr, fill);
	EXPECT_EQ(FillAttributes::FillType::NoFill, fill->get_type());

	auto font = std::static_pointer_cast<FontAttributes>(workingSet.get_object_by_id(102));
	ASSERT_NE(nullptr, font);
	EXPECT_EQ(FontAttributes::FontType::ISO8859_1, font->get_type());

	auto ellipse = std::static_pointer_cast<OutputEllipse>(workingSet.get_object_by_id(103));
	ASSERT_NE(nullptr, ellipse);
	EXPECT_EQ(OutputEllipse::EllipseType::Closed, ellipse->get_ellipse_type());

	auto polygon = std::static_pointer_cast<OutputPolygon>(workingSet.get_object_by_id(104));
	ASSERT_NE(nullptr, polygon);
	EXPECT_EQ(OutputPolygon::PolygonType::Complex, polygon->get_type());

	// The colour map is skipped; whoever references it keeps the default colours.
	EXPECT_EQ(nullptr, workingSet.get_object_by_id(105));

	auto macro = std::static_pointer_cast<Macro>(workingSet.get_object_by_id(106));
	ASSERT_NE(nullptr, macro);
	EXPECT_EQ(0, macro->get_number_of_commands());

	auto picture = std::static_pointer_cast<PictureGraphic>(workingSet.get_object_by_id(107));
	ASSERT_NE(nullptr, picture);
	EXPECT_TRUE(picture->get_raw_data().empty());

	auto keyGroup = std::static_pointer_cast<KeyGroup>(workingSet.get_object_by_id(108));
	ASSERT_NE(nullptr, keyGroup);
	EXPECT_EQ(4, keyGroup->get_number_children());

	auto window = std::static_pointer_cast<WindowMask>(workingSet.get_object_by_id(109));
	ASSERT_NE(nullptr, window);
	EXPECT_EQ(WindowMask::WindowType::Freeform, window->get_window_type());

	auto referencing = workingSet.get_object_by_id(110);
	ASSERT_NE(nullptr, referencing);
	EXPECT_EQ(0, referencing->get_number_macros());

	workingSet.clear_parse_issues();
	EXPECT_TRUE(workingSet.get_parse_issues().empty());
}

TEST(VT_PARSE_POLICY_TESTS, TolerantStillRejectsWhatCannotBeWalked)
{
	// Truncated object
	{
		VirtualTerminalServerManagedWorkingSet workingSet;
		workingSet.set_parse_policy(Policy::Tolerant);
		Bytes pool = working_set();
		append(pool, Bytes(fillType.begin(), fillType.begin() + 5));
		EXPECT_FALSE(parse(workingSet, pool));
	}
	// Unknown object type: its length cannot be known
	{
		VirtualTerminalServerManagedWorkingSet workingSet;
		workingSet.set_parse_policy(Policy::Tolerant);
		Bytes pool = working_set();
		append(pool, { 0x2C, 0x01, 200, 0, 0, 0, 0, 0 });
		EXPECT_FALSE(parse(workingSet, pool));
	}
	// A second Working Set object makes the root ambiguous
	{
		VirtualTerminalServerManagedWorkingSet workingSet;
		workingSet.set_parse_policy(Policy::Tolerant);
		Bytes pool = working_set();
		append(pool, working_set(1));
		EXPECT_FALSE(parse(workingSet, pool));
	}
	// Picture graphic whose declared pixel data is missing
	{
		VirtualTerminalServerManagedWorkingSet workingSet;
		workingSet.set_parse_policy(Policy::Tolerant);
		Bytes pool = working_set();
		append(pool, Bytes(pictureFormat.begin(), pictureFormat.end() - 2));
		EXPECT_FALSE(parse(workingSet, pool));
	}
}

TEST(VT_PARSE_POLICY_TESTS, DuplicateObjectIdIsReportedAndTheLastOneWins)
{
	VirtualTerminalServerManagedWorkingSet workingSet;
	workingSet.set_parse_policy(Policy::Tolerant);
	Bytes pool = working_set();
	append(pool, sentinel(500));
	Bytes replacement = sentinel(500);
	replacement[4] = 7; // Different background colour
	append(pool, replacement);
	ASSERT_TRUE(parse(workingSet, pool));
	ASSERT_EQ(1U, workingSet.get_parse_issues().size());
	EXPECT_EQ(500, workingSet.get_parse_issues()[0].objectID);
	EXPECT_EQ(7, std::static_pointer_cast<FillAttributes>(workingSet.get_object_by_id(500))->get_background_color());

	// A later object pool transfer may replace objects of an earlier one: not a duplicate.
	Bytes update;
	append(update, sentinel(500));
	ASSERT_TRUE(parse(workingSet, update));
	EXPECT_EQ(1U, workingSet.get_parse_issues().size());
}

TEST(VT_PARSE_POLICY_TESTS, AlarmMaskKeepsItsAcousticSignal)
{
	// Valid values are stored as sent; before, the signal was always the default (Highest).
	VirtualTerminalServerManagedWorkingSet workingSet;
	Bytes pool = working_set();
	append(pool, { 0x64, 0x00, 2, 1, 0xFF, 0xFF, 2, 3, 0, 0 }); // Low priority, no sound
	ASSERT_TRUE(parse(workingSet, pool));
	auto alarm = std::static_pointer_cast<AlarmMask>(workingSet.get_object_by_id(100));
	ASSERT_NE(nullptr, alarm);
	EXPECT_EQ(AlarmMask::Priority::Low, alarm->get_mask_priority());
	EXPECT_EQ(AlarmMask::AcousticSignal::None, alarm->get_signal_priority());
	EXPECT_TRUE(workingSet.get_parse_issues().empty());
}
