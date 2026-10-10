//================================================================================================
/// @file isobus_virtual_terminal_server.cpp
///
/// @brief Implements portions of an abstract VT server.
/// @author Adrian Del Grosso
///
/// @copyright 2023 Adrian Del Grosso
//================================================================================================
#include "isobus/isobus/isobus_virtual_terminal_server.hpp"
#include "isobus/isobus/can_general_parameter_group_numbers.hpp"
#include "isobus/isobus/can_message.hpp"
#include "isobus/isobus/can_network_manager.hpp"
#include "isobus/isobus/can_stack_logger.hpp"
#include "isobus/utility/system_timing.hpp"
#include "isobus/utility/to_string.hpp"

#include <iomanip>
#include <set>
#include <sstream>

namespace isobus
{
	/// @brief Extracts the low byte from a 16-bit value.
	/// @param value The value to extract the low byte from.
	/// @returns The low byte of the value.
	static constexpr std::uint8_t get_low_byte(std::uint16_t value) noexcept
	{
		return static_cast<std::uint8_t>(value & 0xFFU);
	}

	/// @brief Extracts the high byte from a 16-bit value.
	/// @param value The value to extract the high byte from.
	/// @returns The high byte of the value.
	static constexpr std::uint8_t get_high_byte(std::uint16_t value) noexcept
	{
		return static_cast<std::uint8_t>((value >> 8) & 0xFFU);
	}

	/// @brief Creates a mask for a bit in an 8-bit value.
	/// @param bitIndex The zero-based bit index.
	/// @returns A mask with the requested bit set, or zero if the index is invalid.
	static constexpr std::uint8_t get_bit(std::uint8_t bitIndex) noexcept
	{
		return (bitIndex < 8U) ? static_cast<std::uint8_t>(1U << bitIndex) : static_cast<std::uint8_t>(0U);
	}

	/// @brief Extracts a byte from a 32-bit value.
	/// @param value The value to extract the byte from.
	/// @param byteIndex The zero-based byte index.
	/// @returns The requested byte, or zero if the index is invalid.
	static constexpr std::uint8_t get_byte(std::uint32_t value, std::uint8_t byteIndex) noexcept
	{
		return (byteIndex < 4U) ? static_cast<std::uint8_t>((value >> (byteIndex * 8U)) & 0xFFU) : static_cast<std::uint8_t>(0U);
	}

	/// @brief Extracts the low 16 bits from a 32-bit value.
	/// @param value The value to extract the low bits from.
	/// @returns The low 16 bits of the value.
	static constexpr std::uint16_t get_low_16_bits(std::uint32_t value) noexcept
	{
		return static_cast<std::uint16_t>(value & 0xFFFFU);
	}

	/// @brief Reads a little-endian 16-bit value from a byte vector.
	/// @param data The vector containing the encoded value.
	/// @param index The index of the first byte. The vector must contain at least two bytes beginning at this index.
	/// @returns The decoded 16-bit value.
	static std::uint16_t get_little_endian_uint16(const std::vector<std::uint8_t> &data, std::size_t index)
	{
		const auto lowByte = static_cast<std::uint16_t>(data[index]);
		const auto highByte = static_cast<std::uint16_t>(data[index + 1]);

		return static_cast<std::uint16_t>(lowByte | static_cast<std::uint16_t>(highByte << 8));
	}

	/// @brief Reads a little-endian 32-bit value from a byte vector.
	/// @param data The vector containing the encoded value.
	/// @param index The index of the first byte. The vector must contain at least four bytes beginning at this index.
	/// @returns The decoded 32-bit value.
	static std::uint32_t get_little_endian_uint32(const std::vector<std::uint8_t> &data, std::size_t index)
	{
		return static_cast<std::uint32_t>(data[index]) |
		  (static_cast<std::uint32_t>(data[index + 1]) << 8) |
		  (static_cast<std::uint32_t>(data[index + 2]) << 16) |
		  (static_cast<std::uint32_t>(data[index + 3]) << 24);
	}

	static bool object_is_visible_from(std::uint16_t currentID, std::uint16_t targetID,
	                                   const std::shared_ptr<VirtualTerminalServerManagedWorkingSet> &workingSet,
	                                   std::set<std::uint16_t> &path)
	{
		if (currentID == targetID) return true;
		if ((NULL_OBJECT_ID == currentID) || path.count(currentID)) return false;
		const auto object = workingSet->get_object_by_id(currentID);
		if (!object) return false;
		if ((object->get_object_type() == VirtualTerminalObjectType::Container) &&
		    std::static_pointer_cast<Container>(object)->get_hidden()) return false;
		path.insert(currentID);
		for (std::uint16_t index = 0; index < object->get_number_children(); ++index)
			if (object_is_visible_from(object->get_child_id(index), targetID, workingSet, path)) { path.erase(currentID); return true; }
		path.erase(currentID);
		return false;
	}

	static bool object_is_on_active_mask(std::uint16_t targetID,
	                                     const std::shared_ptr<VirtualTerminalServerManagedWorkingSet> &workingSet)
	{
		const auto root = workingSet->get_working_set_object();
		if (!root || root->get_object_type() != VirtualTerminalObjectType::WorkingSet) return false;
		const auto maskID = std::static_pointer_cast<WorkingSet>(root)->get_active_mask();
		std::set<std::uint16_t> path;
		if (object_is_visible_from(maskID, targetID, workingSet, path)) return true;
		const auto mask = workingSet->get_object_by_id(maskID);
		std::uint16_t softKeyMask = NULL_OBJECT_ID;
		if (mask && mask->get_object_type() == VirtualTerminalObjectType::DataMask)
			softKeyMask = std::static_pointer_cast<DataMask>(mask)->get_soft_key_mask();
		else if (mask && mask->get_object_type() == VirtualTerminalObjectType::AlarmMask)
			softKeyMask = std::static_pointer_cast<AlarmMask>(mask)->get_soft_key_mask();
		return object_is_visible_from(softKeyMask, targetID, workingSet, path);
	}

	VirtualTerminalServer::VirtualTerminalServer(std::shared_ptr<InternalControlFunction> controlFunctionToUse) :
	  languageCommandInterface(controlFunctionToUse, true),
	  serverInternalControlFunction(controlFunctionToUse)
	{
	}

	VirtualTerminalServer ::~VirtualTerminalServer()
	{
		if (initialized)
		{
			CANNetworkManager::CANNetwork.remove_any_control_function_parameter_group_number_callback(static_cast<std::uint32_t>(CANLibParameterGroupNumber::ECUtoVirtualTerminal),
			                                                                                          process_rx_message,
			                                                                                          this);
			CANNetworkManager::CANNetwork.remove_any_control_function_parameter_group_number_callback(static_cast<std::uint32_t>(CANLibParameterGroupNumber::WorkingSetMaster), process_working_set_message, this);
			CANNetworkManager::CANNetwork.remove_any_control_function_parameter_group_number_callback(static_cast<std::uint32_t>(CANLibParameterGroupNumber::WorkingSetMember), process_working_set_message, this);
		}
	}

	void VirtualTerminalServer::initialize()
	{
		if (!initialized)
		{
			CANNetworkManager::CANNetwork.add_any_control_function_parameter_group_number_callback(static_cast<std::uint32_t>(CANLibParameterGroupNumber::ECUtoVirtualTerminal),
			                                                                                       process_rx_message,
			                                                                                       this);
			CANNetworkManager::CANNetwork.add_any_control_function_parameter_group_number_callback(static_cast<std::uint32_t>(CANLibParameterGroupNumber::WorkingSetMaster), process_working_set_message, this);
			CANNetworkManager::CANNetwork.add_any_control_function_parameter_group_number_callback(static_cast<std::uint32_t>(CANLibParameterGroupNumber::WorkingSetMember), process_working_set_message, this);
			initialized = true;
		}
	}

	bool VirtualTerminalServer::get_initialized() const
	{
		return initialized;
	}

	std::shared_ptr<InternalControlFunction> VirtualTerminalServer::get_internal_control_function() const
	{
		return serverInternalControlFunction;
	}

	std::shared_ptr<VirtualTerminalServerManagedWorkingSet> VirtualTerminalServer::get_active_working_set() const
	{
		return activeWorkingSet;
	}

	std::array<std::uint8_t, CAN_DATA_LENGTH> VirtualTerminalServer::make_vt_unsupported_function_message(std::uint8_t unsupportedFunction)
	{
		return {
		  static_cast<std::uint8_t>(Function::UnsupportedVTFunctionMessage),
		  unsupportedFunction,
		  0xFF,
		  0xFF,
		  0xFF,
		  0xFF,
		  0xFF,
		  0xFF
		};
	}

	bool VirtualTerminalServer::should_send_vt_unsupported_function(VTVersion version,
	                                                               bool destinationSpecific,
	                                                               bool functionHandled,
	                                                               std::uint8_t receivedFunction)
	{
		return (version >= VTVersion::Version5) && destinationSpecific && !functionHandled &&
		       (receivedFunction != static_cast<std::uint8_t>(Function::UnsupportedVTFunctionMessage));
	}

	std::array<std::uint8_t, CAN_DATA_LENGTH> VirtualTerminalServer::make_extended_version_response(std::uint8_t function,
	                                                                                                std::uint8_t errorCode)
	{
		return { function, 0xFF, 0xFF, 0xFF, 0xFF, errorCode, 0xFF, 0xFF };
	}

	bool VirtualTerminalServer::should_route_response_to_originator(VTVersion vtVersion,
	                                                               std::uint8_t workingSetVersion)
	{
		return (vtVersion >= VTVersion::Version4) && (workingSetVersion >= 4) && (workingSetVersion != 0xFF);
	}

	std::array<std::uint8_t, CAN_DATA_LENGTH> VirtualTerminalServer::make_identify_vt_response()
	{
		return { static_cast<std::uint8_t>(Function::IdentifyVTMessage),
		         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	}

	std::uint8_t VirtualTerminalServer::make_transaction_byte(
	  VTVersion vtVersion, std::uint8_t workingSetVersion,
	  std::uint8_t transactionNumber)
	{
		return ((vtVersion >= VTVersion::Version6) && (workingSetVersion >= 6) && (workingSetVersion != 0xFF))
		  ? static_cast<std::uint8_t>(((transactionNumber & 0x0FU) << 4U) | 0x0FU)
		  : 0xFF;
	}

	std::array<std::uint8_t, CAN_DATA_LENGTH> VirtualTerminalServer::make_screen_capture_response(
	  std::uint8_t item, std::uint8_t path, std::uint8_t errorCode, std::uint16_t imageId)
	{
		return { static_cast<std::uint8_t>(Function::ScreenCapture), item, path, errorCode,
		         static_cast<std::uint8_t>(errorCode ? 0xFF : get_low_byte(imageId)),
		         static_cast<std::uint8_t>(errorCode ? 0xFF : get_high_byte(imageId)), 0xFF, 0xFF };
	}

	std::array<std::uint8_t, CAN_DATA_LENGTH> VirtualTerminalServer::make_select_active_working_set_response(std::uint8_t errorCode)
	{
		return { static_cast<std::uint8_t>(Function::SelectActiveWorkingSet), errorCode, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	}

	VirtualTerminalBase::GraphicMode VirtualTerminalServer::get_graphic_mode() const
	{
		return VirtualTerminalBase::GraphicMode::TwoHundredFiftySixColour;
	}

	std::uint8_t VirtualTerminalServer::get_powerup_time() const
	{
		return 0xFF;
	}

	std::uint8_t VirtualTerminalServer::get_supported_small_fonts_bitfield() const
	{
		return 0x7F;
	}

	std::uint8_t VirtualTerminalServer::get_supported_large_fonts_bitfield() const
	{
		return 0x7F;
	}

	void VirtualTerminalServer::identify_vt()
	{
		LOG_ERROR("[VT Server]: The Identify VT command is not implemented");
	}

	void VirtualTerminalServer::screen_capture(std::uint8_t item, std::uint8_t path, std::shared_ptr<ControlFunction> requestor)
	{
		(void)item;
		(void)path;
		(void)requestor;
		LOG_ERROR("[VT Server]: The Screen Capture command is not implemented");
	}

	std::uint8_t VirtualTerminalServer::get_user_layout_softkeymask_bg_color() const
	{
		LOG_ERROR("[VT Server]: The Get User Layout Softkeymask background color is not implemented, returning with black");
		return 0;
	}

	void VirtualTerminalServer::transferred_object_pool_parse_start(std::shared_ptr<isobus::VirtualTerminalServerManagedWorkingSet> &ws) const
	{
		(void)ws;
	}

	std::uint8_t VirtualTerminalServer::get_user_layout_datamask_bg_color() const
	{
		LOG_ERROR("[VT Server]: The Get User Layout Datamask background color is not implemented, returning with black");
		return 0;
	}

	EventDispatcher<std::shared_ptr<VirtualTerminalServerManagedWorkingSet>> &VirtualTerminalServer::get_on_repaint_event_dispatcher()
	{
		return onRepaintEventDispatcher;
	}

	EventDispatcher<std::shared_ptr<VirtualTerminalServerManagedWorkingSet>, std::uint16_t, std::uint16_t> &VirtualTerminalServer::get_on_change_active_mask_event_dispatcher()
	{
		return onChangeActiveMaskEventDispatcher;
	}

	EventDispatcher<std::shared_ptr<VirtualTerminalServerManagedWorkingSet>, std::uint16_t, std::uint16_t> &VirtualTerminalServer::get_on_change_active_softkey_mask_event_dispatcher()
	{
		return onChangeActiveSoftKeyMaskEventDispatcher;
	}

	EventDispatcher<std::shared_ptr<VirtualTerminalServerManagedWorkingSet>, std::uint16_t, bool> &VirtualTerminalServer::get_on_focus_object_event_dispatcher()
	{
		return onFocusObjectEventDispatcher;
	}

	LanguageCommandInterface &VirtualTerminalServer::get_language_command_interface()
	{
		return languageCommandInterface;
	}

	bool VirtualTerminalServer::check_if_source_is_managed(const CANMessage &message)
	{
		// Check if we're managing this CF
		bool retVal = false;

		// This is the static callback for the instance.
		// See if we need to set up a new managed working set.
		std::shared_ptr<VirtualTerminalServerManagedWorkingSet> restartedWorkingSet;
		const auto &messageData = message.get_data();
		const auto sourceName = message.get_source_control_function()->get_NAME().get_full_name();
		auto disconnected = std::find(unexpectedlyDisconnectedWorkingSets.begin(),
		                              unexpectedlyDisconnectedWorkingSets.end(), sourceName);
		if (disconnected != unexpectedlyDisconnectedWorkingSets.end())
		{
			const bool restarting = (messageData[0] == static_cast<std::uint8_t>(Function::WorkingSetMaintenanceMessage)) &&
			                        (messageData[2] != 0xFF) &&
			                        (0 != (messageData[1] & 0x01));
			if (!restarting)
				return false;
			unexpectedlyDisconnectedWorkingSets.erase(disconnected);
		}
		for (const auto &cf : managedWorkingSetList)
		{
			if (cf->contains_control_function(message.get_source_control_function()))
			{
				const auto &data = message.get_data();
				const bool repeatedInitiatingMaintenance =
				  cf->is_master(message.get_source_control_function()) &&
				  (data[0] == static_cast<std::uint8_t>(Function::WorkingSetMaintenanceMessage)) &&
				  (data[2] != 0xFF) &&
				  (0 != (data[1] & 0x01));
				if (repeatedInitiatingMaintenance)
				{
					restartedWorkingSet = cf;
				}
				else
				{
					retVal = !cf->is_deletion_requested();
				}
				break;
			}
		}

		if (nullptr != restartedWorkingSet)
		{
			LOG_WARNING("[VT Server]: Working Set %u restarted; suspending its previous object pool.", restartedWorkingSet->get_control_function()->get_address());
			suspend_working_set(restartedWorkingSet);
			managedWorkingSetList.erase(
			  std::remove(managedWorkingSetList.begin(), managedWorkingSetList.end(), restartedWorkingSet),
			  managedWorkingSetList.end());
		}

		if (!retVal)
		{
			const auto &data = message.get_data();
            // Legacy clients can query cached versions before their first heartbeat.
            // Establish the provisional WS so Get Versions and a following Load
            // Version can run; maintenance supplies its actual version afterward.
            if (data[0] == static_cast<std::uint8_t>(Function::GetVersionsMessage) &&
                message.get_destination_control_function() == serverInternalControlFunction)
            {
                auto ws = std::make_shared<VirtualTerminalServerManagedWorkingSet>(message.get_source_control_function());
                ws->set_version(2);
                ws->set_working_set_maintenance_message_timestamp_ms(SystemTiming::get_timestamp_ms());
                managedWorkingSetList.push_back(ws);
                return true;
            }
			if ((data[0] == static_cast<std::uint8_t>(Function::WorkingSetMaintenanceMessage)) &&
			    ((data[2] == 0xFF) || (data[1] & 0x01))) // G.3: VT2 uses reserved FF flags, not an initiating bit
			{
				// This CF is probably trying to initiate communication with us.
				auto workingSet = std::make_shared<VirtualTerminalServerManagedWorkingSet>(message.get_source_control_function());
				// Publish a fully initialized session. The application's timeout
				// polling must never observe the default timestamp (zero) and retire
				// a freshly received initiating maintenance message as expired.
				workingSet->set_working_set_maintenance_message_timestamp_ms(SystemTiming::get_timestamp_ms());
				workingSet->set_version(data[2]);

				LOG_INFO("[VT Server]: Client %u initiated working set maintenance messages with version %u", workingSet->get_control_function()->get_address(), data[2]);
				if (data[2] > get_vt_version_byte(get_version()))
				{
					LOG_WARNING("[VT Server]: Client %u version %u is higher than our reported version, which is %u", workingSet->get_control_function()->get_address(), data[2], get_vt_version_byte(get_version()));
				}
				managedWorkingSetList.push_back(std::move(workingSet));
				retVal = true;
			}
		}
		return retVal;
	}

	bool VirtualTerminalServer::is_function_available(VTVersion version, Function function)
	{
		VTVersion minimum = VTVersion::Version2OrOlder;
		switch (function)
		{
			case Function::VTOnUserLayoutHideShowMessage:
			case Function::GetSupportedWidecharsMessage:
			case Function::GetWindowMaskDataMessage:
			case Function::GetSupportedObjectsMessage:
			case Function::IdentifyVTMessage:
			case Function::LockUnlockMaskCommand:
			case Function::ExecuteMacroCommand:
			case Function::ChangeObjectLabelCommand:
			case Function::ChangePolygonPointCommand:
			case Function::ChangePolygonScaleCommand:
			case Function::GraphicsContextCommand:
			case Function::GetAttributeValueMessage:
			case Function::SelectColourMapCommand:
				minimum = VTVersion::Version4;
				break;
			case Function::ExecuteExtendedMacroCommand:
			case Function::ExtendedGetVersionsMessage:
			case Function::ExtendedStoreVersionCommand:
			case Function::ExtendedLoadVersionCommand:
			case Function::ExtendedDeleteVersionCommand:
			case Function::AuxiliaryCapabilitiesRequest:
				minimum = VTVersion::Version5;
				break;
			case Function::ScreenCapture:
			case Function::SelectActiveWorkingSet:
				minimum = VTVersion::Version6;
				break;
			default:
				break;
		}
		return version >= minimum;
	}

	void VirtualTerminalServer::execute_macro_as_rx_message(const CANMessage &message)
	{
		if ((message.get_destination_control_function() == serverInternalControlFunction) &&
		    (message.get_source_control_function() != nullptr) &&
		    ((CAN_DATA_LENGTH <= message.get_data_length()) ||
		     ((message.get_data_length() > 5) && message.get_uint8_at(0) == static_cast<std::uint8_t>(Function::ChangeStringValueCommand))))
		{
			process_rx_message(message, this);
		}
	}

	bool VirtualTerminalServer::execute_macro(std::uint16_t objectIDOfMacro, std::shared_ptr<VirtualTerminalServerManagedWorkingSet> workingSet)
	{
		if (!workingSet || macroExecutionDepth >= 32)
		{
			macroExecutionFailed = true;
			return false;
		}
		if (macroExecutionDepth == 0) macroExecutionFailed = false;
		++macroExecutionDepth;
		auto object = workingSet->get_object_by_id(objectIDOfMacro);
		bool retVal = false;

		if ((nullptr != object) && (VirtualTerminalObjectType::Macro == object->get_object_type()))
		{
			auto macro = std::static_pointer_cast<Macro>(object);

			if (macro->get_are_command_packets_valid())
			{
				LOG_DEBUG("[VT Server]: Executing macro %u", macro->get_id());
				retVal = true;

				for (std::uint8_t j = 0; j < macro->get_number_of_commands(); j++)
				{
					std::vector<std::uint8_t> commandPacket;

					if (macro->get_command_packet(j, commandPacket))
					{
						if (commandPacket.empty() || !is_function_available(get_version(), static_cast<Function>(commandPacket[0])))
						{
							macroExecutionFailed = true;
							break;
						}
						isobus::CANMessage message(isobus::CANMessage::Type::Receive,
						                           isobus::CANIdentifier(0x14E70000),
						                           commandPacket,
						                           workingSet->get_control_function(),
						                           get_internal_control_function(),
						                           workingSet->get_control_function()->get_can_port());
						LOG_DEBUG("[VT Server]: Executing macro command %u", j);
						execute_macro_as_rx_message(message);
						if (macroExecutionFailed) break;
					}
				}
			}
		}
		--macroExecutionDepth;
		if (!retVal) macroExecutionFailed = true;
		return retVal && !macroExecutionFailed;
	}

	CANIdentifier::CANPriority VirtualTerminalServer::get_priority() const
	{
		return (VTVersion::Version6 == get_version()) ? CANIdentifier::CANPriority::Priority5 : CANIdentifier::CANPriority::PriorityLowest7;
	}

	std::uint8_t VirtualTerminalServer::next_transaction_byte(
	  const std::shared_ptr<ControlFunction> &destination) const
	{
		if (!destination || get_version() < VTVersion::Version6) return 0xFF;
		auto workingSet = std::find_if(managedWorkingSetList.begin(), managedWorkingSetList.end(),
		  [&destination](const auto &ws) { return ws && ws->get_control_function() &&
		    ws->get_control_function()->get_NAME().get_full_name() == destination->get_NAME().get_full_name(); });
		if (workingSet == managedWorkingSetList.end() || (*workingSet)->get_version() < 6) return 0xFF;
		std::lock_guard<std::mutex> lock(pendingActivationMutex);
		auto &number = transactionNumbers[destination->get_NAME().get_full_name()];
		const auto result = make_transaction_byte(get_version(), (*workingSet)->get_version(), number);
		number = static_cast<std::uint8_t>((number + 1U) & 0x0FU);
		return result;
	}

	bool VirtualTerminalServer::send_tracked_activation(const std::uint8_t *data,
	                                                    std::uint32_t length,
	                                                    const std::shared_ptr<ControlFunction> &destination,
	                                                    std::uint8_t tanIndex) const
	{
		if (!data || !length || !destination) return false;
		auto ws = std::find_if(managedWorkingSetList.begin(), managedWorkingSetList.end(), [&destination](const auto &candidate) {
			return candidate && candidate->get_control_function() && candidate->get_control_function()->get_NAME() == destination->get_NAME();
		});
		const bool tracked = get_version() >= VTVersion::Version6 && ws != managedWorkingSetList.end() && (*ws)->get_version() >= 6;
		std::lock_guard<std::mutex> lock(pendingActivationMutex);
		const std::size_t idOffset = (data[0] <= 1) ? 2 : 1;
		const auto superseded = [&](const auto &pending) {
			return pending.destination && pending.destination->get_NAME() == destination->get_NAME() &&
			       pending.data.size() > idOffset + 1 && length > idOffset + 1 && pending.data[0] == data[0] &&
			       pending.data[idOffset] == data[idOffset] && pending.data[idOffset + 1] == data[idOffset + 1];
		};
		if (tracked && tanIndex != 0xFF && tanIndex < length &&
		    std::any_of(pendingActivations.begin(), pendingActivations.end(), [&](const auto &pending) {
			    return !superseded(pending) && pending.destination && pending.destination->get_NAME() == destination->get_NAME() &&
			           pending.tanIndex != 0xFF && pending.tanIndex < pending.data.size() &&
			           (pending.data[pending.tanIndex] & 0xF0U) == (data[tanIndex] & 0xF0U);
		    })) return false;
		const bool sent = CANNetworkManager::CANNetwork.send_can_message(
		  static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
		  data, length, serverInternalControlFunction, destination, get_priority());
		if (sent && tracked)
		{
			// H.1: preserve the unacknowledged chain's retry budget. Held events
			// arriving every 200 ms must not postpone failure indefinitely.
			std::uint8_t attempts = 1;
			std::uint32_t timestamp = SystemTiming::get_timestamp_ms();
			for (const auto &pending : pendingActivations)
				if (superseded(pending)) { attempts = pending.attempts; timestamp = pending.timestamp; break; }
			pendingActivations.erase(std::remove_if(pendingActivations.begin(), pendingActivations.end(), superseded), pendingActivations.end());
			pendingActivations.push_back({std::vector<std::uint8_t>(data, data + length), destination, tanIndex, attempts, timestamp});
		}
		return sent;
	}

	void VirtualTerminalServer::acknowledge_activation(const CANMessage &message)
	{
		const auto &data = message.get_data(); if (data.empty() || !message.get_source_control_function()) return;
		std::lock_guard<std::mutex> lock(pendingActivationMutex);
		pendingActivations.erase(std::remove_if(pendingActivations.begin(), pendingActivations.end(), [&](const auto &pending) {
			if (!pending.destination || pending.data.empty() || pending.data[0] != data[0] || pending.destination->get_NAME().get_full_name() != message.get_source_control_function()->get_NAME().get_full_name()) return false;
			// H.19 places the acknowledged String Object ID in bytes 4-5,
			// unlike H.18's outgoing bytes 2-3. There is no TAN in this pair.
			if (data[0] == static_cast<std::uint8_t>(Function::VTChangeStringValueMessage))
				return data.size() >= 5 && pending.data.size() >= 3 &&
				       data[3] == pending.data[1] && data[4] == pending.data[2];
			const std::size_t idOffset = (data[0] <= 1) ? 2 : 1;
			if (data.size() <= idOffset + 1 || pending.data.size() <= idOffset + 1 ||
			    data[idOffset] != pending.data[idOffset] || data[idOffset + 1] != pending.data[idOffset + 1]) return false;
			if (data[0] <= 1 && (data.size() < 7 || pending.data.size() < 7 ||
			    !std::equal(data.begin() + 1, data.begin() + 7, pending.data.begin() + 1))) return false;
			if (data[0] == 9 && (data.size() < 7 || pending.data.size() < 7 ||
			    !std::equal(data.begin() + 1, data.begin() + 7, pending.data.begin() + 1))) return false;
			if (data[0] == 3 && (data.size() < 5 || pending.data.size() < 5 ||
			    data[3] != pending.data[3] || data[4] != pending.data[4])) return false;
			if (data[0] == 5 && (data.size() < 8 || pending.data.size() < 8 ||
			    !std::equal(data.begin() + 4, data.begin() + 8, pending.data.begin() + 4))) return false;
			if (pending.tanIndex != 0xFF)
				return data.size() > pending.tanIndex && pending.data.size() > pending.tanIndex &&
				       (data[pending.tanIndex] & 0xF0U) == (pending.data[pending.tanIndex] & 0xF0U);
			return data.size() >= 3 && pending.data.size() >= 3 && data[1] == pending.data[1] && data[2] == pending.data[2];
		}), pendingActivations.end());
	}

	void VirtualTerminalServer::update_activation_transactions()
	{
		std::vector<std::shared_ptr<ControlFunction>> failedDestinations;
		{
			std::lock_guard<std::mutex> lock(pendingActivationMutex);
			for (auto it = pendingActivations.begin(); it != pendingActivations.end();) {
				if (!SystemTiming::time_expired_ms(it->timestamp, 300)) { ++it; continue; }
				// Annex H permits the original activation followed by up to three retries.
				if (it->attempts >= 4 || !it->destination) {
					if (it->destination) failedDestinations.push_back(it->destination);
					it = pendingActivations.erase(it); continue;
				}
				if (CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU), it->data.data(), it->data.size(), serverInternalControlFunction, it->destination, get_priority())) ++it->attempts;
				it->timestamp = SystemTiming::get_timestamp_ms(); ++it;
			}
		}
		for (const auto &destination : failedDestinations) {
			const auto name = destination->get_NAME().get_full_name();
			if (std::find(unexpectedlyDisconnectedWorkingSets.begin(), unexpectedlyDisconnectedWorkingSets.end(), name) == unexpectedlyDisconnectedWorkingSets.end())
				unexpectedlyDisconnectedWorkingSets.push_back(name);
			auto ws = std::find_if(managedWorkingSetList.begin(), managedWorkingSetList.end(), [&](const auto &candidate) { return candidate && candidate->get_control_function() && candidate->get_control_function()->get_NAME().get_full_name() == name; });
			if (ws != managedWorkingSetList.end()) { suspend_working_set(*ws); (*ws)->request_deletion(); }
		}
	}

	std::uint8_t VirtualTerminalServer::get_vt_version_byte(VTVersion version)
	{
		std::uint8_t retVal = 2;

		switch (version)
		{
			case VTVersion::Version3:
			{
				retVal = 3;
			}
			break;

			case VTVersion::Version4:
			{
				retVal = 4;
			}
			break;

			case VTVersion::Version5:
			{
				retVal = 5;
			}
			break;

			case VTVersion::Version6:
			{
				retVal = 6;
			}
			break;

			default:
			{
				// Report version 2
			}
			break;
		}
		return retVal;
	}

	bool VirtualTerminalServer::process_stateless_messages(const CANMessage &message)
	{
		bool retVal = false;
		const auto &data = message.get_data();
		if (data.size() < CAN_DATA_LENGTH || !is_function_available(get_version(), static_cast<Function>(data[0]))) return false;
		switch (static_cast<Function>(data.at(0)))
		{
		case Function::GetMemoryMessage:
			{
				const auto requiredMemory = get_little_endian_uint32(data, 2);
				bool isEnoughMemory = get_is_enough_memory(requiredMemory);
				LOG_INFO("[VT Server]: An ecu requested %u bytes of memory.", requiredMemory);

				if (!isEnoughMemory)
				{
					LOG_WARNING("[VT Server]: Callback indicated there is NOT enough memory.", requiredMemory);
				}
				else
				{
					LOG_DEBUG("[VT Server]: Callback indicated there may be enough memory, but since there is overhead associated to object storage it is impossible to be sure.", requiredMemory);
				}

				std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = { 0 };
				buffer[0] = static_cast<std::uint8_t>(Function::GetMemoryMessage);
				buffer[1] = get_vt_version_byte(get_version());
				buffer[2] = static_cast<std::uint8_t>(!isEnoughMemory);
				buffer[3] = 0xFF; // Reserved
				buffer[4] = 0xFF; // Reserved
				buffer[5] = 0xFF; // Reserved
				buffer[6] = 0xFF; // Reserved
				buffer[7] = 0xFF; // Reserved
				CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
				                                               buffer.data(),
				                                               CAN_DATA_LENGTH,
				                                               serverInternalControlFunction,
				                                               message.get_source_control_function(),
				                                               get_priority());
				retVal = true;
			}
			break;

			case Function::AuxiliaryCapabilitiesRequest:
			{
				send_auxiliary_capabilities_response(data[1], message.get_source_control_function());
				retVal = true;
			}
			break;

			case Function::GetNumberOfSoftKeysMessage:
			{
				std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = { 0 };
				buffer[0] = static_cast<std::uint8_t>(Function::GetNumberOfSoftKeysMessage);
				buffer[1] = get_version() >= VTVersion::Version4 ? get_number_of_navigation_soft_keys() : 0xFF;
				buffer[2] = 0xFF; // Reserved
				buffer[3] = 0xFF; // Reserved
				buffer[4] = get_soft_key_descriptor_x_pixel_width(); // Width of the softkey descriptor in pixels
				buffer[5] = get_soft_key_descriptor_y_pixel_height(); // Height of the softkey descriptor in pixels
				buffer[6] = get_number_of_possible_virtual_soft_keys_in_soft_key_mask(); // Number of possible virtual Soft Keys in a Soft Key Mask
				buffer[7] = get_number_of_physical_soft_keys(); // No physical softkeys

				CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
				                                               buffer.data(),
				                                               CAN_DATA_LENGTH,
				                                               serverInternalControlFunction,
				                                               message.get_source_control_function(),
				                                               get_priority());
				retVal = true;
			}
			break;

			case Function::GetTextFontDataMessage:
			{
				std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = { 0 };
				buffer[0] = static_cast<std::uint8_t>(Function::GetTextFontDataMessage);
				buffer[1] = 0xFF; // Reserved
				buffer[2] = 0xFF; // Reserved
				buffer[3] = 0xFF; // Reserved
				buffer[4] = 0xFF; // Reserved
				buffer[5] = get_supported_small_fonts_bitfield(); // Say we support all small fonts
				buffer[6] = get_supported_large_fonts_bitfield(); // Say we support all large fonts
				buffer[7] = 0x8F; // Support normal, bold, italic, proportional
				CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
				                                               buffer.data(),
				                                               CAN_DATA_LENGTH,
				                                               serverInternalControlFunction,
				                                               message.get_source_control_function(),
				                                               get_priority());
				retVal = true;
			}
			break;

			case Function::GetHardwareMessage:
			{
				std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = { 0 };
				buffer[0] = static_cast<std::uint8_t>(Function::GetHardwareMessage);
				buffer[1] = get_powerup_time();
				buffer[2] = static_cast<std::uint8_t>(get_graphic_mode()); // 256 Colour Mode by default
				buffer[3] = get_supported_hardware_features();
				buffer[4] = get_low_byte(get_data_mask_area_size_x_pixels()); // X Pixels LSB
				buffer[5] = get_high_byte(get_data_mask_area_size_x_pixels()); // X Pixels MSB
				buffer[6] = get_low_byte(get_data_mask_area_size_y_pixels()); // Y Pixels LSB
				buffer[7] = get_high_byte(get_data_mask_area_size_y_pixels()); // Y Pixels MSB
				CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
				                                               buffer.data(),
				                                               CAN_DATA_LENGTH,
				                                               serverInternalControlFunction,
				                                               message.get_source_control_function(),
				                                               get_priority());
				retVal = true;
			}
			break;

			case Function::GetSupportedWidecharsMessage:
			{
				std::vector<std::uint8_t> wideCharRangeArray;
				std::uint8_t numberOfRanges = 0;
				std::uint8_t codePlane = data.at(1);
				std::uint16_t firstWideCharInInquiryRange = get_little_endian_uint16(data, 2);
				std::uint16_t lastWideCharInInquiryRange = get_little_endian_uint16(data, 4);
				auto errorCode = get_supported_wide_chars(codePlane, firstWideCharInInquiryRange, lastWideCharInInquiryRange, numberOfRanges, wideCharRangeArray);

				std::vector<std::uint8_t> buffer;
				buffer.push_back(static_cast<std::uint8_t>(Function::GetSupportedWidecharsMessage));
				buffer.push_back(codePlane);
				buffer.push_back(get_low_byte(firstWideCharInInquiryRange));
				buffer.push_back(get_high_byte(firstWideCharInInquiryRange));
				buffer.push_back(get_low_byte(lastWideCharInInquiryRange));
				buffer.push_back(get_high_byte(lastWideCharInInquiryRange));
				buffer.push_back(static_cast<std::uint8_t>(errorCode));
				buffer.push_back(numberOfRanges);

				for (const auto &range : wideCharRangeArray)
				{
					buffer.push_back(range);
				}
				CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
				                                               buffer.data(),
				                                               static_cast<std::uint32_t>(buffer.size()),
				                                               serverInternalControlFunction,
				                                               message.get_source_control_function(),
				                                               get_priority());
				retVal = true;
			}
			break;

			case Function::ScreenCapture:
			{
				screen_capture(data[1], data[2], message.get_source_control_function());
				retVal = true;
			}
			break;

			case Function::IdentifyVTMessage:
			{
				identify_vt();
				if (message.get_destination_control_function() == serverInternalControlFunction)
				{
					const auto response = make_identify_vt_response();
					CANNetworkManager::CANNetwork.send_can_message(
					  static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
					  response.data(), response.size(), serverInternalControlFunction,
					  message.get_source_control_function(), get_priority());
				}
				retVal = true;
			}
			break;

			case Function::GetSupportedObjectsMessage:
			{
				// D.14 is a capability query from any CF, before WS registration.
				if (get_version() >= VTVersion::Version4)
				{
					send_supported_objects(message.get_source_control_function());
					retVal = true;
				}
			}
			break;

			case Function::GetWindowMaskDataMessage:
			{
				send_get_window_mask_data_response(message.get_source_control_function());
				retVal = true;
			}
			break;

			default:
				break;
		}
		return retVal;
	}

	bool VirtualTerminalServer::process_connection_dependent_messages(const CANMessage &message, std::shared_ptr<VirtualTerminalServerManagedWorkingSet> managedWorkingSet)
	{
		const auto &data = message.get_data();
		if (!managedWorkingSet || data.empty() || !is_function_available(get_version(), static_cast<Function>(data[0]))) return false;
		const auto function = static_cast<Function>(data.at(0));
		if (!managedWorkingSet->is_master(message.get_source_control_function()) &&
		    is_working_set_master_only_function(function))
		{
			send_acknowledgement(AcknowledgementType::Negative,
			                     static_cast<std::uint32_t>(CANLibParameterGroupNumber::ECUtoVirtualTerminal),
			                     serverInternalControlFunction, message.get_source_control_function());
			return true;
		}
		bool retVal = true;
		switch (function)
		{

			case Function::GetMemoryMessage:
			{
				// The response is handled in process_stateless_messages
				// but save the size requested for later use if we have a connected working set
				const auto requiredMemory = get_little_endian_uint32(data, 2);
				managedWorkingSet->set_iop_size(requiredMemory);
			}
			break;

			case Function::ObjectPoolTransferMessage:
			{
				if (managedWorkingSet->get_pool_transfer_out_of_memory()) break;
				std::uint64_t total = data.size() - 1;
				for (std::size_t index = 0; index < managedWorkingSet->get_number_iop_files(); ++index)
					total += managedWorkingSet->get_iop_raw_data(index).size();
				if (total > UINT32_MAX || !get_is_enough_memory(static_cast<std::uint32_t>(total)))
				{
					managedWorkingSet->set_pool_transfer_out_of_memory();
					LOG_WARNING("[VT Server]: Object pool transfer exceeded the memory budget");
					break;
				}
				managedWorkingSet->add_iop_raw_data(std::vector<std::uint8_t>(data.begin() + 1, data.end()));
			}
			break;

			case Function::ExtendedGetVersionsMessage:
			{
				const auto versions = get_extended_versions(
				  managedWorkingSet->get_control_function()->get_NAME());
				std::vector<std::uint8_t> buffer = {
				  static_cast<std::uint8_t>(Function::ExtendedGetVersionsMessage),
				  static_cast<std::uint8_t>(std::min<std::size_t>(versions.size(), 255))
				};
				for (std::size_t index = 0; index < versions.size() && index < 255; ++index)
					buffer.insert(buffer.end(), versions[index].begin(), versions[index].end());
				while (buffer.size() < CAN_DATA_LENGTH)
					buffer.push_back(0xFF);
				CANNetworkManager::CANNetwork.send_can_message(
				  static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
				  buffer.data(), static_cast<std::uint32_t>(buffer.size()),
				  serverInternalControlFunction, message.get_source_control_function(), get_priority());
			}
			break;

			case Function::ExtendedStoreVersionCommand:
			{
				std::uint8_t error = 0;
				if (data.size() != 33)
				{
					error = 0x02;
				}
				else
				{
					std::vector<std::uint8_t> label(data.begin() + 1, data.end());
					const bool blank = std::all_of(label.begin(), label.end(), [](std::uint8_t value) { return value == 0x20; });
					if (blank && get_extended_versions(managedWorkingSet->get_control_function()->get_NAME()).empty())
					{
						error = 0x02;
					}
					else if (!managedWorkingSet->get_any_object_pools())
					{
						error = 0x08;
					}
					else
					{
						std::vector<std::uint8_t> completePool;
						for (std::size_t index = 0; index < managedWorkingSet->get_number_iop_files(); ++index)
						{
							const auto &segment = managedWorkingSet->get_iop_raw_data(index);
							completePool.insert(completePool.end(), segment.begin(), segment.end());
						}
						if (!save_version(completePool, label,
						                  managedWorkingSet->get_control_function()->get_NAME()))
							error = 0x08;
					}
				}
				send_extended_version_response(data[0], error, message.get_source_control_function());
			}
			break;

			case Function::ExtendedLoadVersionCommand:
			{
				if (data.size() != 33)
				{
					send_extended_version_response(data[0], 0x02, message.get_source_control_function());
					break;
				}
				std::vector<std::uint8_t> label(data.begin() + 1, data.end());
				auto loadedVersion = load_version(label, managedWorkingSet->get_control_function()->get_NAME());
				if (loadedVersion.empty())
				{
					send_extended_version_response(data[0], 0x02, message.get_source_control_function());
				}
				else
				{
					managedWorkingSet->set_iop_size(static_cast<std::uint32_t>(loadedVersion.size()));
					managedWorkingSet->add_iop_raw_data(loadedVersion);
					managedWorkingSet->set_was_object_pool_loaded_from_non_volatile_memory(true, {});
					managedWorkingSet->set_pending_load_version_response_function(data[0], {});
					managedWorkingSet->start_parsing_thread();
				}
			}
			break;

			case Function::ExtendedDeleteVersionCommand:
			{
				std::uint8_t error = 0;
				if (data.size() != 33)
				{
					error = 0x02;
				}
				else
				{
					std::vector<std::uint8_t> label(data.begin() + 1, data.end());
					const bool wildcard = (label[0] == '*') &&
					  std::all_of(label.begin() + 1, label.end(), [](std::uint8_t value) { return value == 0x20; });
					bool deleted = false;
					if (wildcard && get_version() >= VTVersion::Version6)
						deleted = delete_all_extended_versions(managedWorkingSet->get_control_function()->get_NAME());
					else
						deleted = delete_version(label, managedWorkingSet->get_control_function()->get_NAME());
					if (!deleted)
						error = 0x02;
				}
				send_extended_version_response(data[0], error, message.get_source_control_function());
			}
			break;

			case Function::GetVersionsMessage:
			{
				auto versions = get_versions(message.get_source_control_function()->get_NAME());

				std::vector<std::uint8_t> buffer;
				buffer.push_back(static_cast<std::uint8_t>(Function::GetVersionsResponse));

				LOG_DEBUG("[VT Server]: Client %u requests stored versions", message.get_source_control_function()->get_address());

				if (versions.size() > 255)
				{
					LOG_WARNING("[VT Server]: get_versions returned too many versions! This client should really delete some.");
				}

				buffer.push_back(static_cast<std::uint8_t>(versions.size() & 0xFF));

				for (const auto &version : versions)
				{
					for (const auto &versionByte : version)
					{
						buffer.push_back(versionByte);
					}
				}

				while (buffer.size() < CAN_DATA_LENGTH)
				{
					buffer.push_back(0xFF);
				}
				CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
				                                               buffer.data(),
				                                               static_cast<std::uint32_t>(buffer.size()),
				                                               serverInternalControlFunction,
				                                               message.get_source_control_function(),
				                                               get_priority());
			}
			break;

			case Function::LoadVersionCommand:
			{
				std::vector<std::uint8_t> versionLabel;

				versionLabel.reserve(VERSION_LABEL_LENGTH);

				for (std::uint_fast8_t i = 0; i < VERSION_LABEL_LENGTH; i++)
				{
					versionLabel.push_back(data[i + 1]);
				}

				auto loadedVersion = load_version(versionLabel, message.get_source_control_function()->get_NAME());
				if (!loadedVersion.empty())
				{
					managedWorkingSet->set_iop_size(static_cast<std::uint32_t>(loadedVersion.size()));
					managedWorkingSet->add_iop_raw_data(loadedVersion);
				}
				else
				{
					send_load_version_response(0x01, message.get_source_control_function());
					LOG_ERROR("[VT Server]: Failed to load requested object pool version");
				}

				if (managedWorkingSet->get_any_object_pools())
				{
					managedWorkingSet->set_was_object_pool_loaded_from_non_volatile_memory(true, {});
					managedWorkingSet->set_pending_load_version_response_function(
					  static_cast<std::uint8_t>(Function::LoadVersionCommand), {});
					managedWorkingSet->start_parsing_thread();
					LOG_DEBUG("[VT Server]: Starting parsing thread for loaded pool data.");
				}
			}
			break;

			case Function::StoreVersionCommand:
			{
				if (managedWorkingSet->get_any_object_pools())
				{
					std::vector<std::uint8_t> versionLabel;
					bool allPoolsSaved = true;
					versionLabel.reserve(VERSION_LABEL_LENGTH);

					for (std::uint_fast8_t i = 0; i < VERSION_LABEL_LENGTH; i++)
					{
						versionLabel.push_back(data[i + 1]);
					}

					std::vector<std::uint8_t> completePool;
					for (std::size_t i = 0; i < managedWorkingSet->get_number_iop_files(); ++i)
					{
						const auto &segment = managedWorkingSet->get_iop_raw_data(i);
						completePool.insert(completePool.end(), segment.begin(), segment.end());
					}
					allPoolsSaved = save_version(completePool, versionLabel,
					                             message.get_source_control_function()->get_NAME());

					std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = { 0 };
					buffer[0] = static_cast<std::uint8_t>(Function::StoreVersionCommand);
					buffer[1] = 0xFF; // Reserved
					buffer[2] = 0xFF; // Reserved
					buffer[3] = 0xFF; // Reserved
					buffer[4] = 0xFF; // Reserved
					if (allPoolsSaved)
					{
						buffer[5] = 0; // No error
					}
					else
					{
						buffer[5] = 0x04; // Any other error
					}
					buffer[6] = 0xFF; // Reserved
					buffer[7] = 0xFF; // Reserved
					CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
					                                               buffer.data(),
					                                               CAN_DATA_LENGTH,
					                                               serverInternalControlFunction,
					                                               message.get_source_control_function(),
					                                               get_priority());
				}
				else
				{
					// Whomever this is appears to be behaving badly, send them a NACK
					send_acknowledgement(AcknowledgementType::Negative, static_cast<std::uint32_t>(CANLibParameterGroupNumber::ECUtoVirtualTerminal), serverInternalControlFunction, message.get_source_control_function());
				}
			}
			break;

			case Function::DeleteVersionCommand:
			{
				std::vector<std::uint8_t> versionLabel;
				std::ostringstream nameString;
				nameString << std::hex << std::setfill('0') << std::setw(16) << managedWorkingSet->get_control_function()->get_NAME().get_full_name();
				versionLabel.reserve(VERSION_LABEL_LENGTH);

				for (std::uint_fast8_t i = 0; i < VERSION_LABEL_LENGTH; i++)
				{
					versionLabel.push_back(data[i + 1]);
				}

				const bool wildcard = (versionLabel[0] == '*') &&
				  std::all_of(versionLabel.begin() + 1, versionLabel.end(), [](std::uint8_t value) { return value == 0x20; });
				const bool wasDeleted = (wildcard && get_version() >= VTVersion::Version6)
				  ? delete_all_versions(managedWorkingSet->get_control_function()->get_NAME())
				  : delete_version(versionLabel, managedWorkingSet->get_control_function()->get_NAME());

				if (wasDeleted)
				{
					LOG_INFO("[VT Server]: Deleted an object pool version for client NAME %s", nameString.str().c_str());
					send_delete_version_response(0, message.get_source_control_function());
				}
				else
				{
					LOG_WARNING("[VT Server]: Delete version failed for client NAME %s", nameString.str().c_str());
					send_delete_version_response(get_bit(static_cast<std::uint8_t>(DeleteVersionErrorBit::VersionLabelNotCorrectOrUnknown)), message.get_source_control_function());
				}
			}
			break;

			case Function::EndOfObjectPoolMessage:
			{
				if (managedWorkingSet->get_pool_transfer_out_of_memory())
				{
					// C.2.4: bit 1 in byte 2 reports memory exhausted during transfer.
					const std::array<std::uint8_t, 8> response{0x12, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0xFF};
					CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU), response.data(), response.size(), serverInternalControlFunction, message.get_source_control_function(), get_priority());
					managedWorkingSet->request_deletion();
				}
				else if (managedWorkingSet->get_any_object_pools())
				{
					managedWorkingSet->start_parsing_thread();
				}
				else
				{
					LOG_WARNING("[VT Server]: End of object pool message ignored - no object pools are loaded for the source control function");
				}
			}
			break;

			case Function::WorkingSetMaintenanceMessage:
			{
				managedWorkingSet->set_version(data[2]);
				managedWorkingSet->set_working_set_maintenance_message_timestamp_ms(SystemTiming::get_timestamp_ms());
			}
			break;

			case Function::ChangeNumericValueCommand:
			{
				const auto value = get_little_endian_uint32(data, 4);
				auto objectId = get_little_endian_uint16(data, 1);
				auto lTargetObject = managedWorkingSet->get_object_by_id(objectId);
				bool logSuccess = true;

				if (nullptr != lTargetObject)
				{
					switch (lTargetObject->get_object_type())
					{
						case VirtualTerminalObjectType::InputBoolean:
						{
							std::static_pointer_cast<InputBoolean>(lTargetObject)->set_value(get_byte(value, 0));
							onRepaintEventDispatcher.call(managedWorkingSet);
							send_change_numeric_value_response(objectId, 0, value, message.get_source_control_function());
						}
						break;

						case VirtualTerminalObjectType::InputNumber:
						{
							std::static_pointer_cast<InputNumber>(lTargetObject)->set_value(value);
							onRepaintEventDispatcher.call(managedWorkingSet);
							send_change_numeric_value_response(objectId, 0, value, message.get_source_control_function());
						}
						break;

						case VirtualTerminalObjectType::InputList:
						{
							std::static_pointer_cast<InputList>(lTargetObject)->set_value(get_byte(value, 0));
							onRepaintEventDispatcher.call(managedWorkingSet);
							send_change_numeric_value_response(objectId, 0, value, message.get_source_control_function());
						}
						break;

						case VirtualTerminalObjectType::OutputNumber:
						{
							std::static_pointer_cast<OutputNumber>(lTargetObject)->set_value(value);
							onRepaintEventDispatcher.call(managedWorkingSet);
							send_change_numeric_value_response(objectId, 0, value, message.get_source_control_function());
						}
						break;

						case VirtualTerminalObjectType::OutputList:
						{
							std::static_pointer_cast<OutputList>(lTargetObject)->set_value(get_byte(value, 0));
							onRepaintEventDispatcher.call(managedWorkingSet);
							send_change_numeric_value_response(objectId, 0, value, message.get_source_control_function());
						}
						break;

						case VirtualTerminalObjectType::OutputMeter:
						{
							std::static_pointer_cast<OutputMeter>(lTargetObject)->set_value(get_low_16_bits(value));
							onRepaintEventDispatcher.call(managedWorkingSet);
							send_change_numeric_value_response(objectId, 0, value, message.get_source_control_function());
						}
						break;

						case VirtualTerminalObjectType::OutputLinearBarGraph:
						{
							std::static_pointer_cast<OutputLinearBarGraph>(lTargetObject)->set_value(get_low_16_bits(value));
							onRepaintEventDispatcher.call(managedWorkingSet);
							send_change_numeric_value_response(objectId, 0, value, message.get_source_control_function());
						}
						break;

						case VirtualTerminalObjectType::OutputArchedBarGraph:
						{
							std::static_pointer_cast<OutputArchedBarGraph>(lTargetObject)->set_value(get_low_16_bits(value));
							onRepaintEventDispatcher.call(managedWorkingSet);
							send_change_numeric_value_response(objectId, 0, value, message.get_source_control_function());
						}
						break;

						case VirtualTerminalObjectType::NumberVariable:
						{
							std::static_pointer_cast<NumberVariable>(lTargetObject)->set_value(value);
							onRepaintEventDispatcher.call(managedWorkingSet);
							send_change_numeric_value_response(objectId, 0, value, message.get_source_control_function());
						}
						break;

						case VirtualTerminalObjectType::ObjectPointer:
						{
							std::static_pointer_cast<ObjectPointer>(lTargetObject)->set_value(get_low_16_bits(value));
							onRepaintEventDispatcher.call(managedWorkingSet);
							send_change_numeric_value_response(objectId, 0, value, message.get_source_control_function());
						}
						break;

						case VirtualTerminalObjectType::ExternalObjectPointer:
						{
							std::uint16_t externalReferenceNAMEObjectIdD = get_little_endian_uint16(data, 4);
							std::uint16_t referencedObjectID = get_little_endian_uint16(data, 6);
							std::static_pointer_cast<ExternalObjectPointer>(lTargetObject)->set_external_reference_name_id(externalReferenceNAMEObjectIdD);
							std::static_pointer_cast<ExternalObjectPointer>(lTargetObject)->set_external_object_id(referencedObjectID);
							send_change_numeric_value_response(objectId, 0, value, message.get_source_control_function());
							onRepaintEventDispatcher.call(managedWorkingSet);
						}
						break;

						case VirtualTerminalObjectType::Animation:
						{
							std::static_pointer_cast<Animation>(lTargetObject)->value = static_cast<std::uint8_t>(value);
							onRepaintEventDispatcher.call(managedWorkingSet);
							send_change_numeric_value_response(objectId, 0, value, message.get_source_control_function());
						}
						break;

						default:
						{
							send_change_numeric_value_response(objectId, get_bit(static_cast<std::uint8_t>(ChangeNumericValueErrorBit::InvalidObjectID)), value, message.get_source_control_function());
							LOG_WARNING("[VT Server]: Client %u change numeric value invalid object type. ID: %u", managedWorkingSet->get_control_function()->get_address(), objectId);
							logSuccess = false;
						}
						break;
					}

					if (logSuccess)
					{
						LOG_DEBUG("[VT Server]: Client %u change numeric value command: change object ID %u to be %u", managedWorkingSet->get_control_function()->get_address(), objectId, value);
						process_macro(lTargetObject, isobus::EventID::OnChangeValue, lTargetObject->get_object_type(), managedWorkingSet);
					}
				}
				else
				{
					send_change_numeric_value_response(objectId, get_bit(static_cast<std::uint8_t>(ChangeNumericValueErrorBit::InvalidObjectID)), value, message.get_source_control_function());
					LOG_WARNING("[VT Server]: Client %u change numeric value invalid object ID of %u", managedWorkingSet->get_control_function()->get_address(), objectId);
				}
			}
			break;

			case Function::HideShowObjectCommand:
			{
				auto objectId = get_little_endian_uint16(data, 1);
				auto targetObject = managedWorkingSet->get_object_by_id(objectId);

				if ((nullptr != targetObject) && (VirtualTerminalObjectType::Container == targetObject->get_object_type()))
				{
					std::static_pointer_cast<Container>(targetObject)->set_hidden(0 == data[3]);
					send_hide_show_object_response(objectId, 0, (0 != data[3]), message.get_source_control_function());
					onRepaintEventDispatcher.call(managedWorkingSet);

					if (0 == data[3])
					{
						LOG_DEBUG("[VT Server]: Client %u hide object command %u", managedWorkingSet->get_control_function()->get_address(), objectId);
						process_macro(targetObject, EventID::OnHide, targetObject->get_object_type(), managedWorkingSet);
					}
					else
					{
						LOG_DEBUG("[VT Server]: Client %u show object command %u", managedWorkingSet->get_control_function()->get_address(), objectId);
						process_macro(targetObject, EventID::OnShow, targetObject->get_object_type(), managedWorkingSet);
					}
				}
				else
				{
					send_hide_show_object_response(objectId, get_bit(static_cast<std::uint8_t>(HideShowObjectErrorBit::InvalidObjectID)), (0 != data[3]), message.get_source_control_function());
					LOG_WARNING("[VT Server]: Client %u hide/show object command failed. It can only affect containers! ID: %u", managedWorkingSet->get_control_function()->get_address(), objectId);
				}
			}
			break;

			case Function::EnableDisableObjectCommand:
			{
				auto objectId = get_little_endian_uint16(data, 1);
				auto lTargetObject = managedWorkingSet->get_object_by_id(objectId);

				if (nullptr != lTargetObject)
				{
					if (data[3] <= 1)
					{
						switch (lTargetObject->get_object_type())
						{
							case VirtualTerminalObjectType::InputBoolean:
							{
								std::static_pointer_cast<InputBoolean>(lTargetObject)->set_enabled(0 != data[3]);
								send_enable_disable_object_response(objectId, 0, (0 != data[3]), message.get_source_control_function());
								onRepaintEventDispatcher.call(managedWorkingSet);
							}
							break;

							case VirtualTerminalObjectType::InputList:
							{
								std::static_pointer_cast<InputList>(lTargetObject)->set_option(InputList::Options::Enabled, (0 != data[3]));
								send_enable_disable_object_response(objectId, 0, (0 != data[3]), message.get_source_control_function());
								onRepaintEventDispatcher.call(managedWorkingSet);
							}
							break;

							case VirtualTerminalObjectType::InputString:
							{
								std::static_pointer_cast<InputString>(lTargetObject)->set_enabled((0 != data[3]));
								send_enable_disable_object_response(objectId, 0, (0 != data[3]), message.get_source_control_function());
								onRepaintEventDispatcher.call(managedWorkingSet);
							}
							break;

							case VirtualTerminalObjectType::InputNumber:
							{
								std::static_pointer_cast<InputNumber>(lTargetObject)->set_option2(InputNumber::Options2::Enabled, (0 != data[3]));
								send_enable_disable_object_response(objectId, 0, (0 != data[3]), message.get_source_control_function());
								onRepaintEventDispatcher.call(managedWorkingSet);
							}
							break;

							case VirtualTerminalObjectType::Button:
							{
								std::static_pointer_cast<Button>(lTargetObject)->set_option(Button::Options::Disabled, (0 == data[3]));
								send_enable_disable_object_response(objectId, 0, (0 != data[3]), message.get_source_control_function());
								onRepaintEventDispatcher.call(managedWorkingSet);
							}
							break;

							case VirtualTerminalObjectType::Animation:
							{
								auto animation = std::static_pointer_cast<Animation>(lTargetObject);
								const bool wasEnabled = animation->enabled;
								animation->enabled = (0 != data[3]);
								if (animation->enabled && !wasEnabled)
									animation->value = animation->firstChildIndex;
								if (!animation->enabled && (((animation->options >> 1) & 0x03) == 1))
									animation->value = animation->firstChildIndex;
								send_enable_disable_object_response(objectId, 0, animation->enabled, message.get_source_control_function());
								onRepaintEventDispatcher.call(managedWorkingSet);
							}
							break;

							default:
							{
								send_enable_disable_object_response(objectId, get_bit(static_cast<std::uint8_t>(EnableDisableObjectErrorBit::InvalidObjectID)), (0 != data[3]), message.get_source_control_function());
							}
							break;
						}
					}
					else
					{
						send_enable_disable_object_response(objectId, get_bit(static_cast<std::uint8_t>(EnableDisableObjectErrorBit::InvalidEnableDisableCommandValue)), (0 != data[3]), message.get_source_control_function());
					}
				}
				else
				{
					send_enable_disable_object_response(objectId, get_bit(static_cast<std::uint8_t>(EnableDisableObjectErrorBit::InvalidObjectID)), (0 != data[3]), message.get_source_control_function());
				}
			}
			break;

			case Function::ChangeChildLocationCommand:
			{
				auto parentObjectId = get_little_endian_uint16(data, 1);
				auto objectID = get_little_endian_uint16(data, 3);
				auto parentObject = managedWorkingSet->get_object_by_id(parentObjectId);

				if (nullptr != parentObject)
				{
					auto lTargetObject = managedWorkingSet->get_object_by_id(objectID);

					if (nullptr != lTargetObject)
					{
						auto xRelativeChange = static_cast<std::int8_t>(static_cast<std::int16_t>(data[5]) - 127);
						auto yRelativeChange = static_cast<std::int8_t>(static_cast<std::int16_t>(data[6]) - 127);
						bool anyObjectMatched = parentObject->offset_all_children_with_id(objectID, xRelativeChange, yRelativeChange);

						onRepaintEventDispatcher.call(managedWorkingSet);

						if (anyObjectMatched)
						{
							send_change_child_location_response(parentObjectId, objectID, 0, message.get_source_control_function());
							LOG_DEBUG("[VT Server]: Client %u change child location command. Parent: %u, Target: %u, X-Offset: %d, Y-Offset: %d", managedWorkingSet->get_control_function()->get_address(), parentObjectId, objectID, xRelativeChange, yRelativeChange);
							process_macro(parentObject, EventID::ChangeChildLocation, parentObject->get_object_type(), managedWorkingSet);
						}
						else
						{
							send_change_child_location_response(parentObjectId, objectID, get_bit(static_cast<std::uint8_t>(ChangeChildLocationorPositionErrorBit::TargetObjectDoesNotExistOrIsNotApplicable)), message.get_source_control_function());
							LOG_WARNING("[VT Server]: Client %u change child location failed because the target object with ID %u isn't applicable", managedWorkingSet->get_control_function()->get_address(), objectID);
						}
					}
					else
					{
						send_change_child_location_response(parentObjectId, objectID, get_bit(static_cast<std::uint8_t>(ChangeChildLocationorPositionErrorBit::TargetObjectDoesNotExistOrIsNotApplicable)), message.get_source_control_function());
						LOG_WARNING("[VT Server]: Client %u change child location failed because the target object with ID %u doesn't exist", managedWorkingSet->get_control_function()->get_address(), objectID);
					}
				}
				else
				{
					send_change_child_location_response(parentObjectId, objectID, get_bit(static_cast<std::uint8_t>(ChangeChildLocationorPositionErrorBit::ParentObjectDoesntExistOrIsNotAParentOfSpecifiedObject)), message.get_source_control_function());
					LOG_WARNING("[VT Server]: Client %u change child location failed because the parent object with ID %u doesn't exist", managedWorkingSet->get_control_function()->get_address(), parentObjectId);
				}
			}
			break;

			case Function::ChangeActiveMaskCommand:
			{
				auto workingSetObjectId = get_little_endian_uint16(data, 1);
				auto newActiveMaskObjectId = get_little_endian_uint16(data, 3);
				auto workingSetObject = managedWorkingSet->get_object_by_id(workingSetObjectId);

				if (nullptr != workingSetObject)
				{
					if (nullptr != managedWorkingSet->get_object_by_id(newActiveMaskObjectId))
					{
						std::static_pointer_cast<WorkingSet>(workingSetObject)->set_active_mask(newActiveMaskObjectId);
						send_change_active_mask_response(newActiveMaskObjectId, 0, message.get_source_control_function());
						onChangeActiveMaskEventDispatcher.call(managedWorkingSet, workingSetObjectId, newActiveMaskObjectId);
						LOG_DEBUG("[VT Server]: Client %u changed active mask to object %u for working set object %u", managedWorkingSet->get_control_function()->get_address(), newActiveMaskObjectId, workingSetObjectId);
					}
					else
					{
						send_change_active_mask_response(newActiveMaskObjectId, get_bit(static_cast<std::uint8_t>(ChangeActiveMaskErrorBit::InvalidMaskObjectID)), message.get_source_control_function());
						LOG_WARNING("[VT Server]: Client %u change active mask failed because the new mask object ID %u was not valid.", managedWorkingSet->get_control_function()->get_address(), newActiveMaskObjectId);
					}
				}
				else
				{
					send_change_active_mask_response(newActiveMaskObjectId, get_bit(static_cast<std::uint8_t>(ChangeActiveMaskErrorBit::InvalidWorkingSetObjectID)), message.get_source_control_function());
					LOG_WARNING("[VT Server]: Client %u change active mask failed because the working set object ID %u was not valid.", managedWorkingSet->get_control_function()->get_address(), workingSetObjectId);
				}
			}
			break;

			case Function::GetSupportedObjectsMessage:
			{
				// Handled in process_stateless_messages, also for registered WSs.
				retVal = (get_version() >= VTVersion::Version4);
			}
			break;

			case Function::ChangeStringValueCommand:
			{
				auto objectIdToChange = get_little_endian_uint16(data, 1);
				auto numberOfBytesInString = get_little_endian_uint16(data, 3);
				auto stringObject = managedWorkingSet->get_object_by_id(objectIdToChange);

				if (message.get_data_length() >= static_cast<std::uint32_t>(numberOfBytesInString + 5))
				{
					if (nullptr != stringObject)
					{
						std::string newStringValue;

						for (std::uint32_t i = 0; i < numberOfBytesInString; i++)
						{
							newStringValue.push_back(static_cast<char>(data.at(5 + i)));
						}

						switch (stringObject->get_object_type())
						{
							case VirtualTerminalObjectType::StringVariable:
							{
								auto stringVariable = std::static_pointer_cast<StringVariable>(stringObject);

								// The transferred string is allowed to be smaller than the length of the value attribute of the target object
								// and in this case the VT shall pad the value attribute with space characters.
								while (newStringValue.length() < stringVariable->get_value().length())
								{
									newStringValue.push_back(' ');
								}
								stringVariable->set_value(newStringValue);
								send_change_string_value_response(objectIdToChange, 0, message.get_source_control_function());
								onRepaintEventDispatcher.call(managedWorkingSet);
								LOG_DEBUG("[VT Server]: Client %u change string value command for string variable object %u. Value: " + newStringValue, managedWorkingSet->get_control_function()->get_address(), objectIdToChange);
							}
							break;

							case VirtualTerminalObjectType::OutputString:
							{
								auto outputString = std::static_pointer_cast<OutputString>(stringObject);

								// The transferred string is allowed to be smaller than the length of the value attribute of the target object
								// and in this case the VT shall pad the value attribute with space characters.
								while (newStringValue.length() < outputString->get_value().length())
								{
									newStringValue.push_back(' ');
								}
								outputString->set_value(newStringValue);
								send_change_string_value_response(objectIdToChange, 0, message.get_source_control_function());
								onRepaintEventDispatcher.call(managedWorkingSet);
								LOG_DEBUG("[VT Server]: Client %u change string value command for output string object %u. Value: " + newStringValue, managedWorkingSet->get_control_function()->get_address(), objectIdToChange);
							}
							break;

							case VirtualTerminalObjectType::InputString:
							{
								auto inputString = std::static_pointer_cast<InputString>(stringObject);

								// The transferred string is allowed to be smaller than the length of the value attribute of the target object
								// and in this case the VT shall pad the value attribute with space characters.
								while (newStringValue.length() < inputString->get_value().length())
								{
									newStringValue.push_back(' ');
								}
								inputString->set_value(newStringValue);
								send_change_string_value_response(objectIdToChange, 0, message.get_source_control_function());
								onRepaintEventDispatcher.call(managedWorkingSet);
								LOG_DEBUG("[VT Server]: Client %u change string value command for input string object %u. Value: " + newStringValue, managedWorkingSet->get_control_function()->get_address(), objectIdToChange);
							}
							break;

							default:
							{
								send_change_string_value_response(objectIdToChange, get_bit(static_cast<std::uint8_t>(ChangeStringValueErrorBit::InvalidObjectID)), message.get_source_control_function());
								LOG_WARNING("[VT Server]: Client %u change string value command for object %u failed because the object ID was for an object that isn't a string.", managedWorkingSet->get_control_function()->get_address(), objectIdToChange);
							}
							break;
						}
					}
					else
					{
						send_change_string_value_response(objectIdToChange, get_bit(static_cast<std::uint8_t>(ChangeStringValueErrorBit::InvalidObjectID)), message.get_source_control_function());
						LOG_WARNING("[VT Server]: Client %u change string value command for object %u failed because the object ID was invalid.", managedWorkingSet->get_control_function()->get_address(), objectIdToChange);
					}
				}
				else
				{
					send_change_string_value_response(objectIdToChange, get_bit(static_cast<std::uint8_t>(ChangeStringValueErrorBit::AnyOtherError)), message.get_source_control_function());
					LOG_WARNING("[VT Server]: Client %u change string value command for object %u failed because data length is not valid when compared to the amount sent.", managedWorkingSet->get_control_function()->get_address(), objectIdToChange);
				}
			}
			break;

			case Function::ChangeFillAttributesCommand:
			{
				auto objectIdToChange = get_little_endian_uint16(data, 1);
				auto fillPatternID = get_little_endian_uint16(data, 5);
				auto object = managedWorkingSet->get_object_by_id(objectIdToChange);
				auto fillPatternObject = managedWorkingSet->get_object_by_id(fillPatternID);

				if ((nullptr != object) && (VirtualTerminalObjectType::FillAttributes == object->get_object_type()))
				{
					auto fillObject = std::static_pointer_cast<FillAttributes>(object);

					if (((nullptr != fillPatternObject) && (VirtualTerminalObjectType::PictureGraphic == fillPatternObject->get_object_type())) || (NULL_OBJECT_ID == fillPatternID))
					{
						if (data[3] <= static_cast<std::uint8_t>(FillAttributes::FillType::FillWithPatternGivenByFillPatternAttribute))
						{
							fillObject->set_fill_pattern(fillPatternID);
							fillObject->set_type(static_cast<FillAttributes::FillType>(data[3]));
							fillObject->set_background_color(data[4]);
							send_change_fill_attributes_response(objectIdToChange, 0, message.get_source_control_function());
							onRepaintEventDispatcher.call(managedWorkingSet);
							LOG_DEBUG("[VT Server]: Client %u change fill attributes command for object %u", managedWorkingSet->get_control_function()->get_address(), objectIdToChange);
						}
						else
						{
							send_change_fill_attributes_response(objectIdToChange, get_bit(static_cast<std::uint8_t>(ChangeFillAttributesErrorBit::InvalidType)), message.get_source_control_function());
							LOG_WARNING("[VT Server]: Client %u change fill attributes of object %u invalid fill object type. Must be a picture graphic.", managedWorkingSet->get_control_function()->get_address(), objectIdToChange);
						}
					}
					else
					{
						send_change_fill_attributes_response(objectIdToChange, get_bit(static_cast<std::uint8_t>(ChangeFillAttributesErrorBit::InvalidPatternObjectID)), message.get_source_control_function());
						LOG_WARNING("[VT Server]: Client %u change fill attributes invalid pattern object ID of %u for object %u", managedWorkingSet->get_control_function()->get_address(), fillPatternID, objectIdToChange);
					}
				}
				else
				{
					send_change_fill_attributes_response(objectIdToChange, get_bit(static_cast<std::uint8_t>(ChangeFillAttributesErrorBit::InvalidObjectID)), message.get_source_control_function());
					LOG_WARNING("[VT Server]: Client %u change fill attributes invalid object ID of %u", managedWorkingSet->get_control_function()->get_address(), objectIdToChange);
				}
			}
			break;

			case Function::ChangeChildPositionCommand:
			{
				auto parentObjectId = get_little_endian_uint16(data, 1);
				auto objectID = get_little_endian_uint16(data, 3);
				if (message.get_data_length() > CAN_DATA_LENGTH) // Must be at least 9 bytes
				{
					std::uint16_t newXPosition = get_little_endian_uint16(data, 5);
					std::uint16_t newYPosition = get_little_endian_uint16(data, 7);
					auto parentObject = managedWorkingSet->get_object_by_id(parentObjectId);
					auto targetObject = managedWorkingSet->get_object_by_id(objectID);

					if (nullptr != parentObject)
					{
						if (nullptr != targetObject)
						{
							switch (parentObject->get_object_type())
							{
								case VirtualTerminalObjectType::Button:
								case VirtualTerminalObjectType::Container:
								case VirtualTerminalObjectType::AlarmMask:
								case VirtualTerminalObjectType::DataMask:
								case VirtualTerminalObjectType::Key:
								case VirtualTerminalObjectType::WorkingSet:
								case VirtualTerminalObjectType::AuxiliaryInputType2:
								case VirtualTerminalObjectType::WindowMask:
								{
									bool wasFound = false;

									// If a parent object includes the child object multiple times, then each instance will be moved
									for (std::uint16_t i = 0; i < parentObject->get_number_children(); i++)
									{
										if (objectID == parentObject->get_child_id(i))
										{
											wasFound = true;
											parentObject->set_child_x(i, newXPosition);
											parentObject->set_child_y(i, newYPosition);
											onRepaintEventDispatcher.call(managedWorkingSet);
										}
									}

									if (wasFound)
									{
										LOG_DEBUG("[VT Server]: Client %u changed child position: object %u of parent object %u, x: %u, y: %u", managedWorkingSet->get_control_function()->get_address(), objectID, parentObjectId, newXPosition, newYPosition);
										send_change_child_position_response(parentObjectId, objectID, 0, message.get_source_control_function());
										process_macro(parentObject, EventID::OnChangeChildPosition, parentObject->get_object_type(), managedWorkingSet);
									}
									else
									{
										LOG_WARNING("[VT Server]: Client %u change child position error. Target object does not exist or is not applicable: object %u of parent object %u, x: %u, y: %u", managedWorkingSet->get_control_function()->get_address(), objectID, parentObjectId, newXPosition, newYPosition);
										send_change_child_position_response(parentObjectId, objectID, get_bit(static_cast<std::uint8_t>(ChangeChildLocationorPositionErrorBit::TargetObjectDoesNotExistOrIsNotApplicable)), message.get_source_control_function());
									}
								}
								break;

								default:
								{
									LOG_WARNING("[VT Server]: Client %u change child position error. Parent object type cannot be targeted by this command: object %u of parent object %u, x: %u, y: %u", managedWorkingSet->get_control_function()->get_address(), objectID, parentObjectId, newXPosition, newYPosition);
									send_change_child_position_response(parentObjectId, objectID, get_bit(static_cast<std::uint8_t>(ChangeChildLocationorPositionErrorBit::AnyOtherError)), message.get_source_control_function());
								}
								break;
							}
						}
						else
						{
							LOG_WARNING("[VT Server]: Client %u change child position error. Target object does not exist or is not applicable: object %u of parent object %u, x: %u, y: %u", managedWorkingSet->get_control_function()->get_address(), objectID, parentObjectId, newXPosition, newYPosition);
							send_change_child_position_response(parentObjectId, objectID, get_bit(static_cast<std::uint8_t>(ChangeChildLocationorPositionErrorBit::TargetObjectDoesNotExistOrIsNotApplicable)), message.get_source_control_function());
						}
					}
					else
					{
						LOG_WARNING("[VT Server]: Client %u change child position error. Parent object does not exist or is not applicable: object %u of parent object %u, x: %u, y: %u", managedWorkingSet->get_control_function()->get_address(), objectID, parentObjectId, newXPosition, newYPosition);
						send_change_child_position_response(parentObjectId, objectID, get_bit(static_cast<std::uint8_t>(ChangeChildLocationorPositionErrorBit::ParentObjectDoesntExistOrIsNotAParentOfSpecifiedObject)), message.get_source_control_function());
					}
				}
				else
				{
					LOG_WARNING("[VT Server]: Client %u change child position error. DLC must be 9 bytes for the message to be valid.");
					send_change_child_position_response(parentObjectId, objectID, get_bit(static_cast<std::uint8_t>(ChangeChildLocationorPositionErrorBit::AnyOtherError)), message.get_source_control_function());
				}
			}
			break;

			case Function::GetAttributeValueMessage:
			{
				// F.58/F.59: errors use FFFF in the response Object ID field,
				// echo the requested ID in bytes 5-6 and carry error bits in byte 7.
				const auto objectID = get_little_endian_uint16(data, 1);
				const auto object = managedWorkingSet->get_object_by_id(objectID);
				std::uint32_t value = 0;
				std::uint8_t error = 0;
				if (NULL_OBJECT_ID == objectID || !object) error = 0x01;
				else if (!supports_object_functionally(object->get_object_type())) error = 0x10;
				else if (!object->get_attribute(data[3], value)) error = 0x02;
				std::array<std::uint8_t, CAN_DATA_LENGTH> response{
				  static_cast<std::uint8_t>(Function::GetAttributeValueMessage),
				  get_low_byte(objectID), get_high_byte(objectID), data[3],
				  get_low_byte(value), get_high_byte(value),
				  static_cast<std::uint8_t>(value >> 16), static_cast<std::uint8_t>(value >> 24)};
				if (error)
				{
					response[1] = response[2] = 0xFF;
					response[4] = get_low_byte(objectID);
					response[5] = get_high_byte(objectID);
					response[6] = error;
					response[7] = 0xFF;
				}
				CANNetworkManager::CANNetwork.send_can_message(
				  static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
				  response.data(), response.size(), serverInternalControlFunction,
				  message.get_source_control_function(), get_priority());
			}
			break;

			case Function::ChangeAttributeCommand:
			{
				auto objectID = get_little_endian_uint16(data, 1);
				auto targetObject = managedWorkingSet->get_object_by_id(objectID);
				std::uint8_t attributeID = data[3];
				const auto attributeData = get_little_endian_uint32(data, 4);
				VTObject::AttributeError errorCode = VTObject::AttributeError::AnyOtherError;

				if (targetObject && !supports_object_functionally(targetObject->get_object_type()))
				{
					send_change_attribute_response(objectID, get_bit(static_cast<std::uint8_t>(VTObject::AttributeError::AnyOtherError)), attributeID, message.get_source_control_function());
				}
				else if ((NULL_OBJECT_ID != objectID) && (nullptr != targetObject))
				{
					if (targetObject->set_attribute(attributeID, attributeData, managedWorkingSet->get_object_tree(), errorCode)) // 0 Is always the read-only "type" attribute
					{
						send_change_attribute_response(objectID, 0, data.at(3), message.get_source_control_function());
						LOG_DEBUG("[VT Server]: Client %u changed object %u attribute %u to %u", managedWorkingSet->get_control_function()->get_address(), objectID, attributeID, attributeData);
						onRepaintEventDispatcher.call(managedWorkingSet);
						process_macro(targetObject, EventID::OnChangeAttribute, targetObject->get_object_type(), managedWorkingSet);
					}
					else
					{
						send_change_attribute_response(objectID, get_bit(static_cast<std::uint8_t>(errorCode)), data.at(3), message.get_source_control_function());
						LOG_WARNING("[VT Server]: Client %u change object %u attribute %u to %ul error %u", managedWorkingSet->get_control_function()->get_address(), objectID, attributeID, attributeData, static_cast<std::uint8_t>(errorCode));
					}
				}
				else
				{
					send_change_attribute_response(objectID, get_bit(static_cast<std::uint8_t>(VTObject::AttributeError::InvalidObjectID)), data.at(3), message.get_source_control_function());
					LOG_WARNING("[VT Server]: Client %u change attribute %u invalid object ID of %u", managedWorkingSet->get_control_function()->get_address(), attributeID, objectID);
				}
			}
			break;

			case Function::ChangeSizeCommand:
			{
				auto objectID = get_little_endian_uint16(data, 1);
				auto newWidth = get_little_endian_uint16(data, 3);
				auto newHeight = get_little_endian_uint16(data, 5);
				auto targetObject = managedWorkingSet->get_object_by_id(objectID);

				if (nullptr != targetObject)
				{
					bool success = false;

					switch (targetObject->get_object_type())
					{
						case VirtualTerminalObjectType::OutputMeter:
						{
							if (newWidth == newHeight) // Output meter must be square!
							{
								targetObject->set_width(newWidth);
								targetObject->set_height(newHeight);
								success = true;
								LOG_DEBUG("[VT Server]: Client %u change size command: Object: %u, Width: %u, Height: %u", managedWorkingSet->get_control_function()->get_address(), objectID, newWidth, newHeight);
								onRepaintEventDispatcher.call(managedWorkingSet);
							}
							else
							{
								LOG_WARNING("[VT Server]: Client %u change size command: invalid new size. Meter must be square! Object: %u", managedWorkingSet->get_control_function()->get_address(), objectID);
								send_change_size_response(objectID, get_bit(static_cast<std::uint8_t>(ChangeSizeErrorBit::AnyOtherError)), message.get_source_control_function());
							}
						}
						break;

						case VirtualTerminalObjectType::Animation:
						case VirtualTerminalObjectType::Button:
						case VirtualTerminalObjectType::Container:
						case VirtualTerminalObjectType::InputBoolean:
						case VirtualTerminalObjectType::InputList:
						case VirtualTerminalObjectType::InputString:
						case VirtualTerminalObjectType::InputNumber:
						case VirtualTerminalObjectType::OutputArchedBarGraph:
						case VirtualTerminalObjectType::OutputEllipse:
						case VirtualTerminalObjectType::OutputLine:
						case VirtualTerminalObjectType::OutputLinearBarGraph:
						case VirtualTerminalObjectType::OutputList:
						case VirtualTerminalObjectType::OutputNumber:
						case VirtualTerminalObjectType::OutputPolygon:
						case VirtualTerminalObjectType::OutputRectangle:
						case VirtualTerminalObjectType::OutputString:
						{
							targetObject->set_width(newWidth);
							targetObject->set_height(newHeight);
							success = true;
							LOG_DEBUG("[VT Server]: Client %u change size command: Object: %u, Width: %u, Height: %u", managedWorkingSet->get_control_function()->get_address(), objectID, newWidth, newHeight);
							onRepaintEventDispatcher.call(managedWorkingSet);
						}
						break;

						default:
						{
							LOG_WARNING("[VT Server]: Client %u change size command: invalid object type for object %u", managedWorkingSet->get_control_function()->get_address(), objectID);
							send_change_size_response(objectID, get_bit(static_cast<std::uint8_t>(ChangeSizeErrorBit::AnyOtherError)), message.get_source_control_function());
						}
						break;
					}

					if (success)
					{
						send_change_size_response(objectID, 0, message.get_source_control_function());
						process_macro(targetObject, EventID::OnChangeSize, targetObject->get_object_type(), managedWorkingSet);
					}
				}
				else
				{
					LOG_WARNING("[VT Server]: Client %u change size command: invalid object ID of %u", managedWorkingSet->get_control_function()->get_address(), objectID);
					send_change_size_response(objectID, get_bit(static_cast<std::uint8_t>(ChangeSizeErrorBit::InvalidObjectID)), message.get_source_control_function());
				}
			}
			break;

			case Function::ChangeListItemCommand:
			{
				auto objectID = get_little_endian_uint16(data, 1);
				auto newObjectID = get_little_endian_uint16(data, 4);
				auto listIndex = data[3];
				auto targetObject = managedWorkingSet->get_object_by_id(objectID);
				auto newObject = managedWorkingSet->get_object_by_id(newObjectID);

				if (nullptr != targetObject)
				{
					if ((NULL_OBJECT_ID == newObjectID) || (nullptr != newObject))
					{
						switch (targetObject->get_object_type())
						{
							case VirtualTerminalObjectType::InputList:
							{
								if (std::static_pointer_cast<InputList>(targetObject)->change_list_item(listIndex, newObjectID, managedWorkingSet->get_object_tree()))
								{
									send_change_list_item_response(objectID, newObjectID, 0, listIndex, message.get_source_control_function());
									LOG_DEBUG("[VT Server]: Client %u change list item command: Object ID: %u, New Object ID: %u, Index: %u", managedWorkingSet->get_control_function()->get_address(), objectID, newObjectID, listIndex);
									onRepaintEventDispatcher.call(managedWorkingSet);
								}
								else
								{
									send_change_list_item_response(objectID, newObjectID, get_bit(static_cast<std::uint8_t>(ChangeListItemErrorBit::AnyOtherError)), listIndex, message.get_source_control_function());
									LOG_WARNING("[VT Server]: Client %u change list item command failed. Object ID: %u, New Object ID: %u, Index: %u", managedWorkingSet->get_control_function()->get_address(), objectID, newObjectID, listIndex);
								}
							}
							break;

							case VirtualTerminalObjectType::Animation:
							{
								if (std::static_pointer_cast<Animation>(targetObject)->change_list_item(listIndex, newObjectID, managedWorkingSet->get_object_tree()))
								{
									send_change_list_item_response(objectID, newObjectID, 0, listIndex, message.get_source_control_function());
									onRepaintEventDispatcher.call(managedWorkingSet);
								}
								else send_change_list_item_response(objectID, newObjectID, get_bit(static_cast<std::uint8_t>(ChangeListItemErrorBit::AnyOtherError)), listIndex, message.get_source_control_function());
							}
							break;

							case VirtualTerminalObjectType::ExternalObjectDefinition:
							{
								if (std::static_pointer_cast<ExternalObjectDefinition>(targetObject)->change_object(listIndex, newObjectID))
								{
									send_change_list_item_response(objectID, newObjectID, 0, listIndex, message.get_source_control_function());
									onRepaintEventDispatcher.call(managedWorkingSet);
								}
								else
									send_change_list_item_response(objectID, newObjectID, get_bit(static_cast<std::uint8_t>(ChangeListItemErrorBit::AnyOtherError)), listIndex, message.get_source_control_function());
							}
							break;

							case VirtualTerminalObjectType::OutputList:
							{
								if (std::static_pointer_cast<OutputList>(targetObject)->change_list_item(listIndex, newObjectID, managedWorkingSet->get_object_tree()))
								{
									send_change_list_item_response(objectID, newObjectID, 0, listIndex, message.get_source_control_function());
									LOG_DEBUG("[VT Server]: Client %u change list item command: Object ID: %u, New Object ID: %u, Index: %u", managedWorkingSet->get_control_function()->get_address(), objectID, newObjectID, listIndex);
									onRepaintEventDispatcher.call(managedWorkingSet);
								}
								else
								{
									send_change_list_item_response(objectID, newObjectID, get_bit(static_cast<std::uint8_t>(ChangeListItemErrorBit::AnyOtherError)), listIndex, message.get_source_control_function());
									LOG_WARNING("[VT Server]: Client %u change list item command failed. Object ID: %u, New Object ID: %u, Index: %u", managedWorkingSet->get_control_function()->get_address(), objectID, newObjectID, listIndex);
								}
							}
							break;

							default:
							{
								LOG_WARNING("[VT Server]: Client %u change list item command: invalid object type. Object: %u", managedWorkingSet->get_control_function()->get_address(), objectID);
								send_change_list_item_response(objectID, newObjectID, get_bit(static_cast<std::uint8_t>(ChangeListItemErrorBit::AnyOtherError)), listIndex, message.get_source_control_function());
							}
							break;
						}
					}
					else
					{
						LOG_WARNING("[VT Server]: Client %u change list item command: invalid new object ID of %u", managedWorkingSet->get_control_function()->get_address(), newObjectID);
						send_change_list_item_response(objectID, newObjectID, get_bit(static_cast<std::uint8_t>(ChangeListItemErrorBit::InvalidNewListItemObjectID)), listIndex, message.get_source_control_function());
					}
				}
				else
				{
					LOG_WARNING("[VT Server]: Client %u change list item command: invalid object ID of %u", managedWorkingSet->get_control_function()->get_address(), objectID);
					send_change_list_item_response(objectID, newObjectID, get_bit(static_cast<std::uint8_t>(ChangeListItemErrorBit::InvalidObjectID)), listIndex, message.get_source_control_function());
				}
			}
			break;

			case Function::ChangeFontAttributesCommand:
			{
				auto objectID = get_little_endian_uint16(data, 1);
				auto targetObject = managedWorkingSet->get_object_by_id(objectID);
				std::uint8_t fontColour = data[3];
				std::uint8_t fontSize = data[4];
				std::uint8_t fontType = data[5];
				std::uint8_t fontStyle = data[6];

				if ((nullptr != targetObject) &&
				    (VirtualTerminalObjectType::FontAttributes == targetObject->get_object_type()))
				{
					if (fontSize <= static_cast<std::uint8_t>(FontAttributes::FontSize::Size128x192))
					{
						auto font = std::static_pointer_cast<FontAttributes>(targetObject);
						font->set_colour(fontColour);
						font->set_size(static_cast<FontAttributes::FontSize>(fontSize));
						font->set_type(static_cast<FontAttributes::FontType>(fontType));
						font->set_style(fontStyle);
						LOG_DEBUG("[VT Server]: Client %u change font attributes command: ObjectID: %u", managedWorkingSet->get_control_function()->get_address(), objectID);
						send_change_font_attributes_response(objectID, 0, message.get_source_control_function());
						onRepaintEventDispatcher.call(managedWorkingSet);
					}
					else
					{
						LOG_WARNING("[VT Server]: Client %u change font attributes command: invalid font size %u. ObjectID: %u", managedWorkingSet->get_control_function()->get_address(), fontSize, objectID);
						send_change_font_attributes_response(objectID, get_bit(static_cast<std::uint8_t>(ChangeFontAttributesErrorBit::InvalidSize)), message.get_source_control_function());
					}
				}
				else
				{
					LOG_WARNING("[VT Server]: Client %u change font attributes command: invalid object ID of %u", managedWorkingSet->get_control_function()->get_address(), objectID);
					send_change_font_attributes_response(objectID, get_bit(static_cast<std::uint8_t>(ChangeFontAttributesErrorBit::InvalidObjectID)), message.get_source_control_function());
				}
			}
			break;

			case Function::ChangeLineAttributesCommand:
			{
				auto objectID = get_little_endian_uint16(data, 1);
				auto targetObject = managedWorkingSet->get_object_by_id(objectID);
				std::uint8_t lineColour = data[3];
				std::uint8_t lineWidth = data[4];
				std::uint16_t lineArt = get_little_endian_uint16(data, 5);

				if ((nullptr != targetObject) &&
				    (VirtualTerminalObjectType::LineAttributes == targetObject->get_object_type()))
				{
					auto line = std::static_pointer_cast<LineAttributes>(targetObject);
					line->set_background_color(lineColour);
					line->set_width(lineWidth);
					line->set_line_art_bit_pattern(lineArt);
					LOG_DEBUG("[VT Server]: Client %u change line attributes command: ObjectID: %u", managedWorkingSet->get_control_function()->get_address(), objectID);
					send_change_line_attributes_response(objectID, 0, message.get_source_control_function());
					onRepaintEventDispatcher.call(managedWorkingSet);
				}
				else
				{
					LOG_WARNING("[VT Server]: Client %u change line attributes command: invalid object ID of %u", managedWorkingSet->get_control_function()->get_address(), objectID);
					send_change_line_attributes_response(objectID, get_bit(static_cast<std::uint8_t>(ChangeFontAttributesErrorBit::InvalidObjectID)), message.get_source_control_function());
				}
			}
			break;

			case Function::ChangeSoftKeyMaskCommand:
			{
				auto dataOrAlarmMaskId = get_little_endian_uint16(data, 2);
				auto newSoftKeyMaskId = get_little_endian_uint16(data, 4);
				auto targetMask = managedWorkingSet->get_object_by_id(dataOrAlarmMaskId);
				auto newSoftKeyMask = managedWorkingSet->get_object_by_id(newSoftKeyMaskId);

				if (nullptr != targetMask)
				{
					if ((NULL_OBJECT_ID == newSoftKeyMaskId) || (nullptr != newSoftKeyMask))
					{
						switch (targetMask->get_object_type())
						{
							case VirtualTerminalObjectType::AlarmMask:
							{
								if (std::static_pointer_cast<AlarmMask>(targetMask)->change_soft_key_mask(newSoftKeyMaskId, managedWorkingSet->get_object_tree()))
								{
									LOG_DEBUG("[VT Server]: Client %u change soft key mask command: alarm mask object %u to %u", managedWorkingSet->get_control_function()->get_address(), dataOrAlarmMaskId, newSoftKeyMaskId);
									send_change_soft_key_mask_response(dataOrAlarmMaskId, newSoftKeyMaskId, 0, message.get_source_control_function());
									onChangeActiveSoftKeyMaskEventDispatcher.call(managedWorkingSet, dataOrAlarmMaskId, newSoftKeyMaskId);
									process_macro(targetMask, EventID::OnChangeSoftKeyMask, VirtualTerminalObjectType::AlarmMask, managedWorkingSet);
								}
								else
								{
									LOG_WARNING("[VT Server]: Client %u change soft key mask command: failed to set mask for alarm mask object %u to %u", managedWorkingSet->get_control_function()->get_address(), dataOrAlarmMaskId, newSoftKeyMaskId);
									send_change_soft_key_mask_response(dataOrAlarmMaskId, newSoftKeyMaskId, get_bit(static_cast<std::uint8_t>(ChangeSoftKeyMaskErrorBit::AnyOtherError)), message.get_source_control_function());
								}
							}
							break;

							case VirtualTerminalObjectType::DataMask:
							{
								if (std::static_pointer_cast<DataMask>(targetMask)->change_soft_key_mask(newSoftKeyMaskId, managedWorkingSet->get_object_tree()))
								{
									LOG_DEBUG("[VT Server]: Client %u change soft key mask command: data mask object %u to %u", managedWorkingSet->get_control_function()->get_address(), dataOrAlarmMaskId, newSoftKeyMaskId);
									send_change_soft_key_mask_response(dataOrAlarmMaskId, newSoftKeyMaskId, 0, message.get_source_control_function());
									onChangeActiveSoftKeyMaskEventDispatcher.call(managedWorkingSet, dataOrAlarmMaskId, newSoftKeyMaskId);
									process_macro(targetMask, EventID::OnChangeSoftKeyMask, VirtualTerminalObjectType::DataMask, managedWorkingSet);
								}
								else
								{
									LOG_WARNING("[VT Server]: Client %u change soft key mask command: failed to set mask for data mask object %u to %u", managedWorkingSet->get_control_function()->get_address(), dataOrAlarmMaskId, newSoftKeyMaskId);
									send_change_soft_key_mask_response(dataOrAlarmMaskId, newSoftKeyMaskId, get_bit(static_cast<std::uint8_t>(ChangeSoftKeyMaskErrorBit::AnyOtherError)), message.get_source_control_function());
								}
							}
							break;

							default:
							{
								LOG_WARNING("[VT Server]: Client %u change soft key mask command: invalid object type for object %u", managedWorkingSet->get_control_function()->get_address(), dataOrAlarmMaskId);
								send_change_soft_key_mask_response(dataOrAlarmMaskId, newSoftKeyMaskId, get_bit(static_cast<std::uint8_t>(ChangeSoftKeyMaskErrorBit::AnyOtherError)), message.get_source_control_function());
							}
							break;
						}
					}
					else
					{
						LOG_WARNING("[VT Server]: Client %u change soft key mask command: invalid soft key object ID of %u", managedWorkingSet->get_control_function()->get_address(), newSoftKeyMaskId);
						send_change_soft_key_mask_response(dataOrAlarmMaskId, newSoftKeyMaskId, get_bit(static_cast<std::uint8_t>(ChangeSoftKeyMaskErrorBit::InvalidSoftKeyMaskObjectID)), message.get_source_control_function());
					}
				}
				else
				{
					LOG_WARNING("[VT Server]: Client %u change soft key mask command: invalid data mask or alarm mask object ID of %u", managedWorkingSet->get_control_function()->get_address(), dataOrAlarmMaskId);
					send_change_soft_key_mask_response(dataOrAlarmMaskId, newSoftKeyMaskId, get_bit(static_cast<std::uint8_t>(ChangeSoftKeyMaskErrorBit::InvalidDataOrAlarmMaskObjectID)), message.get_source_control_function());
				}
			}
			break;

			case Function::ChangeBackgroundColourCommand:
			{
				auto objectID = get_little_endian_uint16(data, 1);
				auto targetObject = managedWorkingSet->get_object_by_id(objectID);
				std::uint8_t backgroundColour = data[3];

				if (nullptr != targetObject)
				{
					switch (targetObject->get_object_type())
					{
						case VirtualTerminalObjectType::AuxiliaryInputType2:
						case VirtualTerminalObjectType::WorkingSet:
						case VirtualTerminalObjectType::DataMask:
						case VirtualTerminalObjectType::AlarmMask:
						case VirtualTerminalObjectType::SoftKeyMask:
						case VirtualTerminalObjectType::Key:
						case VirtualTerminalObjectType::Button:
						case VirtualTerminalObjectType::InputNumber:
						case VirtualTerminalObjectType::InputBoolean:
						case VirtualTerminalObjectType::InputString:
						case VirtualTerminalObjectType::OutputString:
						case VirtualTerminalObjectType::OutputNumber:
						case VirtualTerminalObjectType::GraphicsContext:
						case VirtualTerminalObjectType::WindowMask:
						{
							targetObject->set_background_color(backgroundColour);
							LOG_DEBUG("[VT Server]: Client %u change background colour command: colour = %u", managedWorkingSet->get_control_function()->get_address(), objectID, backgroundColour);
							send_change_background_colour_response(objectID, 0, backgroundColour, message.get_source_control_function());
							process_macro(targetObject, EventID::OnChangeBackgroundColour, targetObject->get_object_type(), managedWorkingSet);
							onRepaintEventDispatcher.call(managedWorkingSet);
						}
						break;

						default:
						{
							LOG_WARNING("[VT Server]: Client %u change background colour command: invalid object type for object %u", managedWorkingSet->get_control_function()->get_address(), objectID);
							send_change_background_colour_response(objectID, get_bit(static_cast<std::uint8_t>(ChangeBackgroundColourErrorBit::AnyOtherError)), backgroundColour, message.get_source_control_function());
						}
						break;
					}
				}
				else
				{
					LOG_WARNING("[VT Server]: Client %u change background colour command: invalid object ID of %u", managedWorkingSet->get_control_function()->get_address(), objectID);
					send_change_background_colour_response(objectID, get_bit(static_cast<std::uint8_t>(ChangeBackgroundColourErrorBit::InvalidObjectID)), backgroundColour, message.get_source_control_function());
				}
			}
			break;

			case Function::ChangePriorityCommand:
			{
				auto objectID = get_little_endian_uint16(data, 1);
				auto targetObject = managedWorkingSet->get_object_by_id(objectID);
				std::uint8_t newPriority = data[3];

				if (nullptr != targetObject)
				{
					if (VirtualTerminalObjectType::AlarmMask == targetObject->get_object_type())
					{
						if (newPriority <= static_cast<std::uint8_t>(AlarmMaskPriority::Low))
						{
							send_change_priority_response(objectID, 0, newPriority, message.get_source_control_function());
							LOG_DEBUG("[VT Server]: Client %u change priority command: New Priority %u", managedWorkingSet->get_control_function()->get_address(), newPriority);
							process_macro(targetObject, EventID::OnChangePriority, VirtualTerminalObjectType::AlarmMask, managedWorkingSet);
						}
						else
						{
							send_change_priority_response(objectID, get_bit(static_cast<std::uint8_t>(ChangePriorityErrorBit::InvalidPriority)), newPriority, message.get_source_control_function());
							LOG_WARNING("[VT Server]: Client %u change priority command: Invalid Priority %u. Must be 2 or less.", managedWorkingSet->get_control_function()->get_address(), newPriority);
						}
					}
					else
					{
						send_change_priority_response(objectID, get_bit(static_cast<std::uint8_t>(ChangePriorityErrorBit::AnyOtherError)), newPriority, message.get_source_control_function());
						LOG_WARNING("[VT Server]: Client %u change priority command: invalid object ID of %u - the object must be an alarm mask.", managedWorkingSet->get_control_function()->get_address(), objectID);
					}
				}
				else
				{
					send_change_priority_response(objectID, get_bit(static_cast<std::uint8_t>(ChangePriorityErrorBit::InvalidObjectID)), newPriority, message.get_source_control_function());
					LOG_WARNING("[VT Server]: Client %u change priority command: invalid object ID of %u", managedWorkingSet->get_control_function()->get_address(), objectID);
				}
			}
			break;

			case Function::SelectInputObjectCommand:
			{
				auto objectID = get_little_endian_uint16(data, 1);
				if (NULL_OBJECT_ID == objectID)
				{
					if (0xFF == data[3])
					{
						managedWorkingSet->set_object_focus(NULL_OBJECT_ID);
						onFocusObjectEventDispatcher.call(managedWorkingSet, NULL_OBJECT_ID, false);
						send_select_input_object_response(objectID, 0, SelectInputObjectResponse::ObjectIsNotSelectedOrIsNullOrError, message.get_source_control_function());
					}
					else send_select_input_object_response(objectID, get_bit(static_cast<std::uint8_t>(SelectInputObjectErrorBit::InvalidOptionValue)), SelectInputObjectResponse::ObjectIsNotSelectedOrIsNullOrError, message.get_source_control_function());
					break;
				}
				auto targetObject = managedWorkingSet->get_object_by_id(objectID);

				if (nullptr != targetObject)
				{
					bool disabled = false;
					switch (targetObject->get_object_type())
					{
						case VirtualTerminalObjectType::Button: disabled = std::static_pointer_cast<Button>(targetObject)->get_option(Button::Options::Disabled); break;
						case VirtualTerminalObjectType::InputBoolean: disabled = !std::static_pointer_cast<InputBoolean>(targetObject)->get_enabled(); break;
						case VirtualTerminalObjectType::InputString: disabled = !std::static_pointer_cast<InputString>(targetObject)->get_enabled(); break;
						case VirtualTerminalObjectType::InputList: disabled = !std::static_pointer_cast<InputList>(targetObject)->get_option(InputList::Options::Enabled); break;
						case VirtualTerminalObjectType::InputNumber: disabled = !std::static_pointer_cast<InputNumber>(targetObject)->get_option2(InputNumber::Options2::Enabled); break;
						default: break;
					}
					if (disabled)
					{
						send_select_input_object_response(objectID, get_bit(static_cast<std::uint8_t>(SelectInputObjectErrorBit::ObjectIsDisabled)), SelectInputObjectResponse::ObjectIsNotSelectedOrIsNullOrError, message.get_source_control_function());
						break;
					}
					if (!object_is_on_active_mask(objectID, managedWorkingSet))
					{
						send_select_input_object_response(objectID, get_bit(static_cast<std::uint8_t>(SelectInputObjectErrorBit::ObjectIsNotOnTheActiveMaskOrIsInAHiddenContainer)), SelectInputObjectResponse::ObjectIsNotSelectedOrIsNullOrError, message.get_source_control_function());
						break;
					}
					switch (targetObject->get_object_type())
					{
						case VirtualTerminalObjectType::Button:
						case VirtualTerminalObjectType::Key:
						{
							if (get_vt_version_byte(get_version()) > 3)
							{
								if (0 == data[3])
								{
									send_select_input_object_response(objectID, get_bit(static_cast<std::uint8_t>(SelectInputObjectErrorBit::InvalidOptionValue)), SelectInputObjectResponse::ObjectIsNotSelectedOrIsNullOrError, message.get_source_control_function());
								}
								else if (0xFF == data[3])
								{
									// This removes focus if the ID is NULL_OBJECT_ID, or sets focus if not
									managedWorkingSet->set_object_focus(objectID);
									LOG_DEBUG("[VT Server]: Client %u select input object %u", managedWorkingSet->get_control_function()->get_address(), objectID);
									onFocusObjectEventDispatcher.call(managedWorkingSet, objectID, false);
									send_select_input_object_response(objectID, 0, NULL_OBJECT_ID == objectID ? SelectInputObjectResponse::ObjectIsNotSelectedOrIsNullOrError : SelectInputObjectResponse::ObjectIsSelected, message.get_source_control_function());
									process_macro(targetObject, NULL_OBJECT_ID == objectID ? EventID::OnInputFieldDeselection : EventID::OnInputFieldSelection, targetObject->get_object_type(), managedWorkingSet);
								}
								else
								{
									LOG_WARNING("[VT Server]: Client %u select input object command: Illegal option byte", managedWorkingSet->get_control_function()->get_address(), objectID);
									send_select_input_object_response(objectID, get_bit(static_cast<std::uint8_t>(SelectInputObjectErrorBit::InvalidOptionValue)), SelectInputObjectResponse::ObjectIsNotSelectedOrIsNullOrError, message.get_source_control_function());
								}
							}
							else
							{
								send_select_input_object_response(objectID, get_bit(static_cast<std::uint8_t>(SelectInputObjectErrorBit::AnyOtherError)), SelectInputObjectResponse::ObjectIsNotSelectedOrIsNullOrError, message.get_source_control_function());
								LOG_WARNING("[VT Server]: Client %u select input object command: buttons and keys can only be selected when the server is version 4 or higher.", managedWorkingSet->get_control_function()->get_address(), objectID);
							}
						}
						break;

						case VirtualTerminalObjectType::InputBoolean:
						case VirtualTerminalObjectType::InputNumber:
						case VirtualTerminalObjectType::InputString:
						case VirtualTerminalObjectType::InputList:
						{
							if (0 == data[3])
							{
								// 0 in Version 4+ means to activate the object for input
								managedWorkingSet->set_object_focus(objectID, true);
								LOG_DEBUG("[VT Server]: Client %u select input object %u and open for input", managedWorkingSet->get_control_function()->get_address(), objectID);
								onFocusObjectEventDispatcher.call(managedWorkingSet, objectID, true);
								send_select_input_object_response(objectID, 0, NULL_OBJECT_ID == objectID ? SelectInputObjectResponse::ObjectIsNotSelectedOrIsNullOrError : SelectInputObjectResponse::ObjectIsOpenedForEdit, message.get_source_control_function());
								process_macro(targetObject, NULL_OBJECT_ID == objectID ? EventID::OnInputFieldDeselection : EventID::OnInputFieldSelection, targetObject->get_object_type(), managedWorkingSet);
							}
							else if (0xFF == data[3])
							{
								// This removes focus if the ID is NULL_OBJECT_ID, or sets focus if not
								managedWorkingSet->set_object_focus(objectID);
								LOG_DEBUG("[VT Server]: Client %u select input object %u", managedWorkingSet->get_control_function()->get_address(), objectID);
								onFocusObjectEventDispatcher.call(managedWorkingSet, objectID, false);
								send_select_input_object_response(objectID, 0, NULL_OBJECT_ID == objectID ? SelectInputObjectResponse::ObjectIsNotSelectedOrIsNullOrError : SelectInputObjectResponse::ObjectIsSelected, message.get_source_control_function());
								process_macro(targetObject, NULL_OBJECT_ID == objectID ? EventID::OnInputFieldDeselection : EventID::OnInputFieldSelection, targetObject->get_object_type(), managedWorkingSet);
							}
							else
							{
								LOG_WARNING("[VT Server]: Client %u select input object command: Illegal option byte", managedWorkingSet->get_control_function()->get_address(), objectID);
								send_select_input_object_response(objectID, get_bit(static_cast<std::uint8_t>(SelectInputObjectErrorBit::InvalidOptionValue)), SelectInputObjectResponse::ObjectIsNotSelectedOrIsNullOrError, message.get_source_control_function());
							}
						}
						break;

						default:
						{
							LOG_WARNING("[VT Server]: Client %u select input object command: invalid object type", managedWorkingSet->get_control_function()->get_address(), objectID);
							send_select_input_object_response(objectID, get_bit(static_cast<std::uint8_t>(SelectInputObjectErrorBit::AnyOtherError)), SelectInputObjectResponse::ObjectIsNotSelectedOrIsNullOrError, message.get_source_control_function());
						}
						break;
					}
				}
				else
				{
					send_select_input_object_response(objectID, get_bit(static_cast<std::uint8_t>(SelectInputObjectErrorBit::InvalidObjectID)), SelectInputObjectResponse::ObjectIsNotSelectedOrIsNullOrError, message.get_source_control_function());
					LOG_WARNING("[VT Server]: Client %u select input object command: invalid object ID of %u", managedWorkingSet->get_control_function()->get_address(), objectID);
				}
			}
			break;

			case Function::ChangeObjectLabelCommand:
			{
				const auto labelledObjectID = get_little_endian_uint16(data, 1);
				const auto stringVariableID = get_little_endian_uint16(data, 3);
				const auto fontType = data[5];
				const auto graphicID = get_little_endian_uint16(data, 6);
				std::shared_ptr<ObjectLabelReferenceList> labels;
				for (const auto &entry : managedWorkingSet->get_object_tree())
					if (entry.second && entry.second->get_object_type() == VirtualTerminalObjectType::ObjectLabelRefrenceList)
					{ labels = std::static_pointer_cast<ObjectLabelReferenceList>(entry.second); break; }
				std::uint8_t error = 0;
				if (!labels) error |= 0x08;
				else if (!labels->get_label(labelledObjectID)) error |= 0x01;
				const auto stringObject = managedWorkingSet->get_object_by_id(stringVariableID);
				if ((NULL_OBJECT_ID != stringVariableID) && (!stringObject || stringObject->get_object_type() != VirtualTerminalObjectType::StringVariable)) error |= 0x02;
				if (!((fontType <= 2) || fontType == 4 || fontType == 5 || fontType == 7)) error |= 0x04;
				if ((NULL_OBJECT_ID != graphicID) && !managedWorkingSet->get_object_by_id(graphicID)) error |= 0x10;
				if ((0 == error) && !labels->change_label(labelledObjectID, stringVariableID, fontType, graphicID)) error |= 0x20;
				std::array<std::uint8_t, CAN_DATA_LENGTH> response{static_cast<std::uint8_t>(Function::ChangeObjectLabelCommand), error, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
				CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU), response.data(), response.size(), serverInternalControlFunction, message.get_source_control_function(), get_priority());
			}
			break;

			case Function::ChangeEndPointCommand:
			{
				const auto id = get_little_endian_uint16(data, 1);
				const auto object = managedWorkingSet->get_object_by_id(id);
				std::uint8_t error = 0;
				if (!object || object->get_object_type() != VirtualTerminalObjectType::OutputLine) error = 0x01;
				else if (data[7] > 1) error = 0x02;
				else {
					auto line = std::static_pointer_cast<OutputLine>(object);
					line->set_width(get_little_endian_uint16(data, 3)); line->set_height(get_little_endian_uint16(data, 5));
					line->set_line_direction(static_cast<OutputLine::LineDirection>(data[7]));
					onRepaintEventDispatcher.call(managedWorkingSet);
					process_macro(object, EventID::OnChangeEndpoint, object->get_object_type(), managedWorkingSet);
				}
				std::array<std::uint8_t, 8> response{static_cast<std::uint8_t>(Function::ChangeEndPointCommand), get_low_byte(id), get_high_byte(id), error, 0xFF, 0xFF, 0xFF, 0xFF};
				CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU), response.data(), response.size(), serverInternalControlFunction, message.get_source_control_function(), get_priority());
			}
			break;

			case Function::ChangePolygonScaleCommand:
			{
				const auto id = get_little_endian_uint16(data, 1), width = get_little_endian_uint16(data, 3), height = get_little_endian_uint16(data, 5);
				const auto object = managedWorkingSet->get_object_by_id(id);
				std::uint8_t error = 0;
				if (!object || object->get_object_type() != VirtualTerminalObjectType::OutputPolygon) error = 0x01;
				else if (!std::static_pointer_cast<OutputPolygon>(object)->scale_points(width, height)) error = 0x10;
				else { onRepaintEventDispatcher.call(managedWorkingSet); process_macro(object, EventID::OnChangeSize, object->get_object_type(), managedWorkingSet); }
				std::array<std::uint8_t, 8> response{static_cast<std::uint8_t>(Function::ChangePolygonScaleCommand), get_low_byte(id), get_high_byte(id), get_low_byte(width), get_high_byte(width), get_low_byte(height), get_high_byte(height), error};
				CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU), response.data(), response.size(), serverInternalControlFunction, message.get_source_control_function(), get_priority());
			}
			break;

			case Function::AuxiliaryInputTypeTwoMaintenanceMessage:
			{
				const auto modelIdentificationCode = get_little_endian_uint16(data, 1);
				managedWorkingSet->set_auxiliary_input_state(
				  modelIdentificationCode, data[3], SystemTiming::get_timestamp_ms());
			}
			break;

			case Function::PreferredAssignmentCommand:
			{
				auto parsed = parse_preferred_auxiliary_assignment(data);
				for (auto &assignment : parsed.assignments)
				{
					const auto functionObject = managedWorkingSet->get_object_by_id(assignment.functionObjectID);
					if ((nullptr == functionObject) ||
					    (VirtualTerminalObjectType::AuxiliaryFunctionType2 != functionObject->get_object_type()))
					{
						parsed.errorBitfield |= 0x02;
						if (NULL_OBJECT_ID == parsed.faultingFunctionObjectID)
							parsed.faultingFunctionObjectID = assignment.functionObjectID;
						continue;
					}

					auto inputWorkingSet = std::find_if(
					  managedWorkingSetList.begin(), managedWorkingSetList.end(),
					  [&assignment](const auto &candidate) {
						  return candidate->get_control_function()->get_NAME().get_full_name() == assignment.inputUnitName;
					  });
					if ((inputWorkingSet == managedWorkingSetList.end()) ||
					    ((*inputWorkingSet)->get_auxiliary_input_model_identification_code() != assignment.modelIdentificationCode) ||
					    ((*inputWorkingSet)->get_auxiliary_input_status() != 1) ||
					    SystemTiming::time_expired_ms((*inputWorkingSet)->get_auxiliary_input_maintenance_timestamp_ms(), 300))
					{
						parsed.errorBitfield |= 0x01;
						if (NULL_OBJECT_ID == parsed.faultingFunctionObjectID)
							parsed.faultingFunctionObjectID = assignment.functionObjectID;
						continue;
					}

					const auto inputObject = (*inputWorkingSet)->get_object_by_id(assignment.inputObjectID);
					if ((nullptr == inputObject) ||
					    (VirtualTerminalObjectType::AuxiliaryInputType2 != inputObject->get_object_type()))
					{
						parsed.errorBitfield |= 0x04;
						if (NULL_OBJECT_ID == parsed.faultingFunctionObjectID)
							parsed.faultingFunctionObjectID = assignment.functionObjectID;
						continue;
					}

					const auto functionType = std::static_pointer_cast<AuxiliaryFunctionType2>(functionObject)->get_function_type();
					const auto inputType = std::static_pointer_cast<AuxiliaryInputType2>(inputObject)->get_function_type();
					if (functionType != inputType)
					{
						parsed.errorBitfield |= 0x10;
						if (NULL_OBJECT_ID == parsed.faultingFunctionObjectID)
							parsed.faultingFunctionObjectID = assignment.functionObjectID;
					}
					else
					{
						assignment.functionType = static_cast<std::uint8_t>(functionType);
					}
				}

				if (0 == parsed.errorBitfield)
				{
					const auto functionWorkingSetName = managedWorkingSet->get_control_function()->get_NAME().get_full_name();
					preferredAuxiliaryAssignments[functionWorkingSetName] = parsed.assignments;
					for (auto &existing : managedAuxiliaryAssignments)
					{
						if ((existing.functionWorkingSetName == functionWorkingSetName) &&
						    (AuxiliaryAssignmentState::Failed != existing.state))
						{
							existing.state = AuxiliaryAssignmentState::PendingRemoval;
							existing.attempts = 0;
						}
					}
					for (const auto &assignment : parsed.assignments)
					{
						managedAuxiliaryAssignments.push_back({ assignment,
						                                                functionWorkingSetName,
						                                                AuxiliaryAssignmentState::PendingEnable,
						                                                0, 0 });
					}
				}
				send_preferred_assignment_response(parsed.errorBitfield,
				                                  parsed.faultingFunctionObjectID,
				                                  message.get_source_control_function());
			}
			break;

			case Function::AuxiliaryInputStatusTypeTwoEnableCommand:
			{
				const auto inputObjectID = get_little_endian_uint16(data, 1);
				const auto sourceName = managedWorkingSet->get_control_function()->get_NAME().get_full_name();
				for (auto &assignment : managedAuxiliaryAssignments)
				{
					if ((assignment.assignment.inputUnitName == sourceName) &&
					    (assignment.assignment.inputObjectID == inputObjectID) &&
					    ((AuxiliaryAssignmentState::WaitingEnableResponse == assignment.state) ||
					     (AuxiliaryAssignmentState::WaitingDisableResponse == assignment.state)))
					{
						const bool disabling = AuxiliaryAssignmentState::WaitingDisableResponse == assignment.state;
						assignment.state = ((0 == data[4]) && (data[3] == (disabling ? 0 : 1)))
						  ? (disabling ? AuxiliaryAssignmentState::Failed
						               : AuxiliaryAssignmentState::PendingAssignment)
						  : AuxiliaryAssignmentState::Failed;
						assignment.attempts = 0;
					}
				}
			}
			break;

			case Function::AuxiliaryAssignmentTypeTwoCommand:
			{
				const auto functionObjectID = get_little_endian_uint16(data, 1);
				const auto sourceName = managedWorkingSet->get_control_function()->get_NAME().get_full_name();
				for (auto &assignment : managedAuxiliaryAssignments)
				{
					if ((assignment.functionWorkingSetName == sourceName) &&
					    (assignment.assignment.functionObjectID == functionObjectID) &&
					    ((AuxiliaryAssignmentState::WaitingAssignmentResponse == assignment.state) ||
					     (AuxiliaryAssignmentState::WaitingRemovalResponse == assignment.state)))
					{
						const bool removal = AuxiliaryAssignmentState::WaitingRemovalResponse == assignment.state;
						if (0 != (data[3] & 0x01))
						{
							assignment.state = AuxiliaryAssignmentState::Failed;
						}
						else if (!removal)
						{
							assignment.state = AuxiliaryAssignmentState::Active;
						}
						else
						{
							const bool inputAvailable = std::any_of(
							  managedWorkingSetList.begin(), managedWorkingSetList.end(),
							  [&assignment](const auto &workingSet) {
								  return workingSet->get_control_function()->get_NAME().get_full_name() ==
								         assignment.assignment.inputUnitName;
							  });
							const bool inputStillUsed = std::any_of(
							  managedAuxiliaryAssignments.begin(), managedAuxiliaryAssignments.end(),
							  [&assignment](const auto &other) {
								  return (&other != &assignment) &&
								         (other.assignment.inputUnitName == assignment.assignment.inputUnitName) &&
								         (other.assignment.inputObjectID == assignment.assignment.inputObjectID) &&
								         (AuxiliaryAssignmentState::Active == other.state);
							  });
							assignment.state = (inputStillUsed || !inputAvailable)
							  ? AuxiliaryAssignmentState::Failed
							  : AuxiliaryAssignmentState::PendingDisable;
						}
						assignment.attempts = 0;
						break;
					}
				}
			}
			break;

			case Function::SelectColourMapCommand:
			{
				const auto objectID = get_little_endian_uint16(data, 1);
				std::uint8_t error = 0;
				auto object = managedWorkingSet->get_object_by_id(objectID);
				if ((NULL_OBJECT_ID != objectID) && !object) error = 0x01;
				else if (object && (VirtualTerminalObjectType::ColourMap != object->get_object_type()) &&
				         (VirtualTerminalObjectType::ColourPalette != object->get_object_type())) error = 0x02;
				else
				{
					std::array<VTColourVector, 256> oldColours;
					for (std::uint16_t i = 0; i < 256; ++i) oldColours[i] = managedWorkingSet->get_colour(static_cast<std::uint8_t>(i));
					const bool palette = object && (VirtualTerminalObjectType::ColourPalette == object->get_object_type());
					const bool selected = palette ? managedWorkingSet->select_colour_palette(objectID) :
					  (NULL_OBJECT_ID == objectID ? (managedWorkingSet->select_colour_map(objectID) && managedWorkingSet->select_colour_palette(objectID)) :
					                                managedWorkingSet->select_colour_map(objectID));
					if (!selected) error = 0x04;
					else { on_colour_table_changed(managedWorkingSet, oldColours); onRepaintEventDispatcher.call(managedWorkingSet); }
				}
				const std::array<std::uint8_t, 8> response = { static_cast<std::uint8_t>(Function::SelectColourMapCommand),
				  get_low_byte(objectID), get_high_byte(objectID), error, 0xFF, 0xFF, 0xFF, 0xFF };
				CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
				  response.data(), response.size(), serverInternalControlFunction, message.get_source_control_function(), get_priority());
			}
			break;

			case Function::ExecuteMacroCommand:
			{
				auto objectID = static_cast<std::uint16_t>(data[1]);
				auto targetObject = managedWorkingSet->get_object_by_id(objectID);

				if (nullptr != targetObject)
				{
					if (VirtualTerminalObjectType::Macro == targetObject->get_object_type())
					{
						if (execute_macro(objectID, managedWorkingSet))
						{
							LOG_DEBUG("[VT Server]: Client %u execute macro command %u: completed.", managedWorkingSet->get_control_function()->get_address(), objectID);
							send_execute_macro_or_extended_macro_response(objectID, 0, message.get_source_control_function(), false);
						}
						else
						{
							LOG_ERROR("[VT Server]: Client %u execute macro command: failed. Macro probably contains invalid commands. Object pool state may now be undefined!", managedWorkingSet->get_control_function()->get_address(), objectID);
							send_execute_macro_or_extended_macro_response(objectID, get_bit(static_cast<std::uint8_t>(ExecuteMacroResponseErrorBit::AnyOtherError)), message.get_source_control_function(), false);
						}
					}
					else
					{
						LOG_WARNING("[VT Server]: Client %u execute macro command: object ID %u is not a macro!", managedWorkingSet->get_control_function()->get_address(), objectID);
						send_execute_macro_or_extended_macro_response(objectID, get_bit(static_cast<std::uint8_t>(ExecuteMacroResponseErrorBit::ObjectIsNotAMacro)), message.get_source_control_function(), false);
					}
				}
				else
				{
					LOG_WARNING("[VT Server]: Client %u execute macro command: invalid object ID of %u", managedWorkingSet->get_control_function()->get_address(), objectID);
					send_execute_macro_or_extended_macro_response(objectID, get_bit(static_cast<std::uint8_t>(ExecuteMacroResponseErrorBit::ObjectDoesntExist)), message.get_source_control_function(), false);
				}
			}
			break;

			case Function::ExecuteExtendedMacroCommand:
			{
				auto objectID = get_little_endian_uint16(data, 1);
				auto targetObject = managedWorkingSet->get_object_by_id(objectID);

				if (nullptr != targetObject)
				{
					if (VirtualTerminalObjectType::Macro == targetObject->get_object_type())
					{
						if (execute_macro(objectID, managedWorkingSet))
						{
							LOG_DEBUG("[VT Server]: Client %u execute extended macro command %u: completed.", managedWorkingSet->get_control_function()->get_address(), objectID);
							send_execute_macro_or_extended_macro_response(objectID, 0, message.get_source_control_function(), true);
						}
						else
						{
							LOG_ERROR("[VT Server]: Client %u execute extended macro command: failed. Macro probably contains invalid commands. Object pool state may now be undefined!", managedWorkingSet->get_control_function()->get_address(), objectID);
							send_execute_macro_or_extended_macro_response(objectID, get_bit(static_cast<std::uint8_t>(ExecuteMacroResponseErrorBit::AnyOtherError)), message.get_source_control_function(), true);
						}
					}
					else
					{
						LOG_WARNING("[VT Server]: Client %u execute extended macro command: object ID %u is not a macro!", managedWorkingSet->get_control_function()->get_address(), objectID);
						send_execute_macro_or_extended_macro_response(objectID, get_bit(static_cast<std::uint8_t>(ExecuteMacroResponseErrorBit::ObjectIsNotAMacro)), message.get_source_control_function(), true);
					}
				}
				else
				{
					LOG_WARNING("[VT Server]: Client %u execute extended macro command: invalid object ID of %u", managedWorkingSet->get_control_function()->get_address(), objectID);
					send_execute_macro_or_extended_macro_response(objectID, get_bit(static_cast<std::uint8_t>(ExecuteMacroResponseErrorBit::ObjectDoesntExist)), message.get_source_control_function(), true);
				}
			}
			break;

			case Function::DeleteObjectPoolCommand:
			{
				LOG_INFO("[VT Server]: Client %u requests deletion of object pool from volatile memory.", managedWorkingSet->get_control_function()->get_address());
				if (delete_object_pool(managedWorkingSet->get_control_function()->get_NAME()))
				{
					LOG_INFO("[VT Server]: Client %u object pool has been deactivated.", managedWorkingSet->get_control_function()->get_address());
					send_delete_object_pool_response(0, message.get_source_control_function());
				}
				else
				{
					LOG_ERROR("[VT Server]: Client %u object pool failed to be deactivated.", managedWorkingSet->get_control_function()->get_address());
					send_delete_object_pool_response(get_bit(static_cast<std::uint8_t>(DeleteObjectPoolErrorBit::DeletionError)), message.get_source_control_function());
				}
			}
			break;

			case Function::ChangePolygonPointCommand:
			{
				auto objectID = get_little_endian_uint16(data, 1);
				const std::uint8_t polygonPointIndex = data[3];
				const std::uint16_t newXValue = get_little_endian_uint16(data, 4);
				const std::uint16_t newYValue = get_little_endian_uint16(data, 6);
				auto targetObject = managedWorkingSet->get_object_by_id(objectID);

				if (nullptr != targetObject)
				{
					if (VirtualTerminalObjectType::OutputPolygon == targetObject->get_object_type())
					{
						auto polygon = std::static_pointer_cast<OutputPolygon>(targetObject);

						if (polygon->change_point(polygonPointIndex, newXValue, newYValue))
						{
							LOG_DEBUG("[VT Server]: Client %u change polygon id %u point index %u. X = %u, Y = %u", managedWorkingSet->get_control_function()->get_address(), objectID, polygonPointIndex, newXValue, newYValue);
							send_change_polygon_point_response(objectID, 0, message.get_source_control_function());
						}
						else
						{
							LOG_WARNING("[VT Server]: Client %u change polygon point: the point index of %u is not valid for object %u", managedWorkingSet->get_control_function()->get_address(), polygonPointIndex, objectID);
							send_change_polygon_point_response(objectID, get_bit(static_cast<std::uint8_t>(ChangePolygonPointErrorBit::InvalidPointIndex)), message.get_source_control_function());
						}
					}
					else
					{
						LOG_WARNING("[VT Server]: Client %u change polygon point: object id %u is not an output polygon", managedWorkingSet->get_control_function()->get_address(), objectID);
						send_change_polygon_point_response(objectID, get_bit(static_cast<std::uint8_t>(ChangePolygonPointErrorBit::AnyOtherError)), message.get_source_control_function());
					}
				}
				else
				{
					LOG_WARNING("[VT Server]: Client %u change polygon point: invalid object ID of %u", managedWorkingSet->get_control_function()->get_address(), objectID);
					send_change_polygon_point_response(objectID, get_bit(static_cast<std::uint8_t>(ChangePolygonPointErrorBit::InvalidObjectID)), message.get_source_control_function());
				}
			}
			break;

			case Function::ControlAudioSignalCommand:
			{
				const auto error = control_audio_signal(
				  managedWorkingSet, data[1], get_little_endian_uint16(data, 2),
				  get_little_endian_uint16(data, 4), get_little_endian_uint16(data, 6));
				send_audio_signal_response(error, message.get_source_control_function());
			}
			break;

			case Function::SelectActiveWorkingSet:
			{
				std::uint8_t error = 0;
				std::uint64_t requestedName = 0;
				if (data.size() < 9) error = 0x80;
				else for (std::uint8_t i = 0; i < 8; ++i) requestedName |= static_cast<std::uint64_t>(data[1 + i]) << (8U * i);
				if (!error && activeWorkingSetMasterAddress != managedWorkingSet->get_control_function()->get_address()) error |= 0x01;
				if (!error && activeWorkingSet) {
					auto mask = activeWorkingSet->get_object_by_id(activeWorkingSetDataMaskObjectID);
					if (mask && mask->get_object_type() == VirtualTerminalObjectType::AlarmMask) error |= 0x02;
				}
				auto target = std::find_if(managedWorkingSetList.begin(), managedWorkingSetList.end(), [requestedName](const auto &ws) {
					return ws && ws->get_control_function() && ws->get_control_function()->get_NAME().get_full_name() == requestedName;
				});
				if (!error && target == managedWorkingSetList.end()) error |= 0x04;
				std::shared_ptr<WorkingSet> targetObject;
				if (!error) {
					targetObject = std::dynamic_pointer_cast<WorkingSet>((*target)->get_working_set_object());
					if (!targetObject) error |= 0x08;
				}
				std::shared_ptr<VTObject> targetMask;
				if (!error) {
					targetMask = (*target)->get_object_by_id(targetObject->get_active_mask());
					if (!targetMask || targetMask->get_object_type() != VirtualTerminalObjectType::DataMask) error |= 0x10;
				}
				if (!error) {
					activeWorkingSet = *target;
					activeWorkingSetMasterAddress = (*target)->get_control_function()->get_address();
					activeWorkingSetDataMaskObjectID = targetObject->get_active_mask();
					onChangeActiveMaskEventDispatcher.call(*target, targetObject->get_id(), targetObject->get_active_mask());
				}
				const auto response = make_select_active_working_set_response(error);
				CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU), response.data(), response.size(), serverInternalControlFunction, message.get_source_control_function(), get_priority());
			}
			break;

			case Function::ESCCommand:
			{
				const auto focusedObjectID = managedWorkingSet->get_object_focus();
				if ((NULL_OBJECT_ID == focusedObjectID) ||
				    (!managedWorkingSet->get_is_object_open_for_input()))
				{
					send_esc_response(NULL_OBJECT_ID,
					                  static_cast<std::uint8_t>(ESCMessageErrorCode::NoInputFieldOpen),
					                  message.get_source_control_function());
					break;
				}

				auto focusedObject = managedWorkingSet->get_object_by_id(focusedObjectID);
				managedWorkingSet->set_object_focus(NULL_OBJECT_ID);
				onFocusObjectEventDispatcher.call(managedWorkingSet, NULL_OBJECT_ID, false);
				if (nullptr != focusedObject)
				{
					process_macro(focusedObject, EventID::OnESC, focusedObject->get_object_type(), managedWorkingSet);
				}
				send_esc_response(focusedObjectID, 0, message.get_source_control_function());
			}
			break;

			case Function::SetAudioVolumeCommand:
			{
				const auto error = (data[1] <= 100)
				  ? set_audio_volume(managedWorkingSet, data[1])
				  : static_cast<std::uint8_t>(0x10);
				send_audio_volume_response(error, message.get_source_control_function());
			}
			break;

			case Function::IdentifyVTMessage:
				// Handled before WS registration, including destination-global.
				break;

			case Function::ScreenCapture:
				// Stateless technical-data request, answered before WS registration.
				break;

			case Function::ButtonActivationMessage:
			case Function::SoftKeyActivationMessage:
			case Function::PointingEventMessage:
			case Function::VTSelectInputObjectMessage:
			case Function::VTESCMessage:
			case Function::VTChangeNumericValueMessage:
			case Function::VTChangeActiveMaskMessage:
			case Function::VTChangeStringValueMessage:
			case Function::VTControlAudioSignalTerminationMessage:
			case Function::VTOnUserLayoutHideShowMessage:
			{
				acknowledge_activation(message);
			}
			break;

			default:
				retVal = handles_custom_function(function);
				break;
		}
		return retVal;
	}

	bool VirtualTerminalServer::is_working_set_master_only_function(Function function)
	{
		switch (function)
		{
			case Function::GetMemoryMessage:
			case Function::ObjectPoolTransferMessage:
			case Function::EndOfObjectPoolMessage:
			case Function::GetVersionsMessage:
			case Function::StoreVersionCommand:
			case Function::LoadVersionCommand:
			case Function::DeleteVersionCommand:
			case Function::ExtendedGetVersionsMessage:
			case Function::ExtendedStoreVersionCommand:
			case Function::ExtendedLoadVersionCommand:
			case Function::ExtendedDeleteVersionCommand:
			case Function::DeleteObjectPoolCommand:
			case Function::WorkingSetMaintenanceMessage:
			case Function::PreferredAssignmentCommand:
				return true;
			default:
				return false;
		}
	}

	void VirtualTerminalServer::process_rx_message(const CANMessage &message, void *parent)
	{
		auto parentServer = static_cast<VirtualTerminalServer *>(parent);
		if ((nullptr != message.get_source_control_function()) &&
		    (nullptr != parentServer) &&
		    ((CAN_DATA_LENGTH <= message.get_data_length()) ||
		     ((message.get_data_length() > 5) && (static_cast<std::uint8_t>(Function::ChangeStringValueCommand) == message.get_uint8_at(0))))) // Technically this message can be 6 bytes
		{
			if (static_cast<std::uint32_t>(CANLibParameterGroupNumber::ECUtoVirtualTerminal) == message.get_identifier().get_parameter_group_number())
			{
				const bool directed = message.get_destination_control_function() == parentServer->serverInternalControlFunction;
				const bool globalIdentify = message.get_identifier().get_destination_address() == BROADCAST_CAN_ADDRESS && message.get_uint8_at(0) == static_cast<std::uint8_t>(Function::IdentifyVTMessage);
				if (!directed && !globalIdentify) return;
				if (!is_function_available(parentServer->get_version(), static_cast<Function>(message.get_uint8_at(0))))
				{
					if (directed)
					{
						if (parentServer->get_version() >= VTVersion::Version5)
							parentServer->send_vt_unsupported_function(message.get_uint8_at(0), message.get_source_control_function());
						else
							parentServer->send_acknowledgement(AcknowledgementType::Negative, static_cast<std::uint32_t>(CANLibParameterGroupNumber::ECUtoVirtualTerminal), parentServer->serverInternalControlFunction, message.get_source_control_function());
					}
					return;
				}
				bool responseSent = parentServer->process_stateless_messages(message);
				bool isManaged = parentServer->check_if_source_is_managed(message);
				if (!isManaged && !responseSent)
				{
					// Whomever this is has probably timed out. Send them a NACK
					LOG_WARNING("[VT Server]: Received a non-status message from a client at address %u, but they are not connected to this VT.", message.get_identifier().get_source_address());
					parentServer->send_acknowledgement(AcknowledgementType::Negative, static_cast<std::uint32_t>(CANLibParameterGroupNumber::ECUtoVirtualTerminal), parentServer->get_internal_control_function(), message.get_source_control_function());
				}
				if (isManaged)
				{
					bool connectionMessageHandled = false;
					for (const auto &cf : parentServer->managedWorkingSetList)
					{
						if (cf->contains_control_function(message.get_source_control_function()))
						{
							const auto function = static_cast<Function>(message.get_uint8_at(0));
							const bool member = !cf->is_master(message.get_source_control_function());
							if (member && is_working_set_master_only_function(function))
							{
								parentServer->send_acknowledgement(AcknowledgementType::Negative,
								  static_cast<std::uint32_t>(CANLibParameterGroupNumber::ECUtoVirtualTerminal),
								  parentServer->serverInternalControlFunction, message.get_source_control_function());
								connectionMessageHandled = true;
								continue;
							}
							const bool routeToOriginator = should_route_response_to_originator(
							  parentServer->get_version(), cf->get_version());
							const auto routedSource = routeToOriginator ? message.get_source_control_function() : cf->get_control_function();
							CANMessage routedMessage(message.get_type(), message.get_identifier(), message.get_data(),
							                         routedSource, message.get_destination_control_function(),
							                         message.get_can_port_index(), message.get_timestamp_us());
							connectionMessageHandled = parentServer->process_connection_dependent_messages(routedMessage, cf);
						}
					}
					const bool destinationSpecific =
					  message.get_destination_control_function() == parentServer->serverInternalControlFunction;
					if (parentServer->should_send_vt_unsupported_function(
					      parentServer->get_version(),
					      destinationSpecific,
					      responseSent || connectionMessageHandled,
					      message.get_uint8_at(0)))
					{
						parentServer->send_vt_unsupported_function(message.get_uint8_at(0), message.get_source_control_function());
					}
				}
			}
		}
	}

	void VirtualTerminalServer::process_working_set_message(const CANMessage &message, void *parent)
	{
		auto server = static_cast<VirtualTerminalServer *>(parent);
		if (!server || !message.get_source_control_function() || message.get_data_length() != CAN_DATA_LENGTH) return;
		const auto pgn = message.get_identifier().get_parameter_group_number();
		auto workingSet = std::find_if(server->managedWorkingSetList.begin(), server->managedWorkingSetList.end(),
		                               [&message](const auto &candidate) { return candidate->is_master(message.get_source_control_function()); });
		if (pgn == static_cast<std::uint32_t>(CANLibParameterGroupNumber::WorkingSetMaster))
		{
			const auto count = message.get_uint8_at(0);
			if (count == 0) return;
			if (workingSet == server->managedWorkingSetList.end())
			{
				server->managedWorkingSetList.emplace_back(std::make_shared<VirtualTerminalServerManagedWorkingSet>(message.get_source_control_function()));
				workingSet = std::prev(server->managedWorkingSetList.end());
			}
			(*workingSet)->configure_members(count);
		}
		else if ((pgn == static_cast<std::uint32_t>(CANLibParameterGroupNumber::WorkingSetMember)) &&
		         (workingSet != server->managedWorkingSetList.end()))
		{
			std::uint64_t rawName = 0;
			for (std::uint8_t index = 0; index < 8; ++index)
				rawName |= static_cast<std::uint64_t>(message.get_uint8_at(index)) << (8 * index);
			(*workingSet)->add_member(NAME(rawName));
		}
	}

	bool VirtualTerminalServer::send_acknowledgement(AcknowledgementType type, std::uint32_t parameterGroupNumber, std::shared_ptr<InternalControlFunction> source, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if ((nullptr != source) && (nullptr != destination))
		{
			std::array<std::uint8_t, CAN_DATA_LENGTH> buffer;

			buffer[0] = static_cast<std::uint8_t>(type);
			buffer[1] = 0xFF;
			buffer[2] = 0xFF;
			buffer[3] = 0xFF;
			buffer[4] = destination->get_address();
			buffer[5] = get_byte(parameterGroupNumber, 0);
			buffer[6] = get_byte(parameterGroupNumber, 1);
			buffer[7] = get_byte(parameterGroupNumber, 2);

			retVal = CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::Acknowledge),
			                                                        buffer.data(),
			                                                        CAN_DATA_LENGTH,
			                                                        source,
			                                                        nullptr,
			                                                        get_priority());
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_vt_unsupported_function(std::uint8_t unsupportedFunction, std::shared_ptr<ControlFunction> destination) const
	{
		const auto buffer = make_vt_unsupported_function_message(unsupportedFunction);
		return CANNetworkManager::CANNetwork.send_can_message(
		  static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
		  buffer.data(),
		  buffer.size(),
		  serverInternalControlFunction,
		  destination,
		  get_priority());
	}

	bool VirtualTerminalServer::send_extended_version_response(std::uint8_t function,
	                                                           std::uint8_t errorCode,
	                                                           std::shared_ptr<ControlFunction> destination) const
	{
		const auto buffer = make_extended_version_response(function, errorCode);
		return CANNetworkManager::CANNetwork.send_can_message(
		  static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
		  buffer.data(), buffer.size(), serverInternalControlFunction, destination,
		  get_priority());
	}

	bool VirtualTerminalServer::send_change_active_mask_response(std::uint16_t newMaskObjectID, std::uint8_t errorBitfield, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			const std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = {
				static_cast<std::uint8_t>(Function::ChangeActiveMaskCommand),
				get_low_byte(newMaskObjectID),
				get_high_byte(newMaskObjectID),
				errorBitfield,
				0xFF,
				0xFF,
				0xFF,
				0xFF
			};

			retVal = CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU), buffer.data(), CAN_DATA_LENGTH, serverInternalControlFunction, destination, get_priority());
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_change_attribute_response(std::uint16_t objectID, std::uint8_t errorBitfield, std::uint8_t attributeID, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			const std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = {
				static_cast<std::uint8_t>(Function::ChangeAttributeCommand),
				get_low_byte(objectID),
				get_high_byte(objectID),
				attributeID,
				errorBitfield,
				0xFF,
				0xFF,
				0xFF
			};

			retVal = CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU), buffer.data(), CAN_DATA_LENGTH, serverInternalControlFunction, destination, get_priority());
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_change_background_colour_response(std::uint16_t objectID, std::uint8_t errorBitfield, std::uint8_t colour, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			const std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = {
				static_cast<std::uint8_t>(Function::ChangeBackgroundColourCommand),
				get_low_byte(objectID),
				get_high_byte(objectID),
				colour,
				errorBitfield,
				0xFF,
				0xFF,
				0xFF
			};

			retVal = CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU), buffer.data(), CAN_DATA_LENGTH, serverInternalControlFunction, destination, get_priority());
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_change_child_location_response(std::uint16_t parentObjectID, std::uint16_t objectID, std::uint8_t errorBitfield, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			std::array<std::uint8_t, CAN_DATA_LENGTH> buffer;

			buffer[0] = static_cast<std::uint8_t>(Function::ChangeChildLocationCommand);
			buffer[1] = get_low_byte(parentObjectID);
			buffer[2] = get_high_byte(parentObjectID);
			buffer[3] = get_low_byte(objectID);
			buffer[4] = get_high_byte(objectID);
			buffer[5] = errorBitfield;
			buffer[6] = 0xFF;
			buffer[7] = 0xFF;

			retVal = CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU), buffer.data(), CAN_DATA_LENGTH, serverInternalControlFunction, destination, get_priority());
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_change_child_position_response(std::uint16_t parentObjectID, std::uint16_t objectID, std::uint8_t errorBitfield, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			std::array<std::uint8_t, CAN_DATA_LENGTH> buffer{
				static_cast<std::uint8_t>(Function::ChangeChildPositionCommand),
				get_low_byte(parentObjectID),
				get_high_byte(parentObjectID),
				get_low_byte(objectID),
				get_high_byte(objectID),
				errorBitfield,
				0xFF,
				0xFF
			};

			retVal = CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
			                                                        buffer.data(),
			                                                        CAN_DATA_LENGTH,
			                                                        serverInternalControlFunction,
			                                                        destination,
			                                                        get_priority());
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_change_fill_attributes_response(std::uint16_t objectID, std::uint8_t errorBitfield, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = {
				static_cast<std::uint8_t>(Function::ChangeFillAttributesCommand),
				get_low_byte(objectID),
				get_high_byte(objectID),
				errorBitfield,
				0xFF,
				0xFF,
				0xFF,
				0xFF
			};
			retVal = CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
			                                                        buffer.data(),
			                                                        CAN_DATA_LENGTH,
			                                                        serverInternalControlFunction,
			                                                        destination,
			                                                        get_priority());
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_change_font_attributes_response(std::uint16_t objectID, std::uint8_t errorBitfield, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = {
				static_cast<std::uint8_t>(Function::ChangeFontAttributesCommand),
				get_low_byte(objectID),
				get_high_byte(objectID),
				errorBitfield,
				0xFF,
				0xFF,
				0xFF,
				0xFF
			};
			retVal = CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
			                                                        buffer.data(),
			                                                        CAN_DATA_LENGTH,
			                                                        serverInternalControlFunction,
			                                                        destination,
			                                                        get_priority());
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_change_line_attributes_response(std::uint16_t objectID, std::uint8_t errorBitfield, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = {
				static_cast<std::uint8_t>(Function::ChangeLineAttributesCommand),
				get_low_byte(objectID),
				get_high_byte(objectID),
				errorBitfield,
				0xFF,
				0xFF,
				0xFF,
				0xFF
			};
			retVal = CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
			                                                        buffer.data(),
			                                                        CAN_DATA_LENGTH,
			                                                        serverInternalControlFunction,
			                                                        destination,
			                                                        get_priority());
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_change_list_item_response(std::uint16_t objectID, std::uint16_t newObjectID, std::uint8_t errorBitfield, std::uint8_t listIndex, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = {
				static_cast<std::uint8_t>(Function::ChangeListItemCommand),
				get_low_byte(objectID),
				get_high_byte(objectID),
				listIndex,
				get_low_byte(newObjectID),
				get_high_byte(newObjectID),
				errorBitfield,
				0xFF
			};
			retVal = CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
			                                                        buffer.data(),
			                                                        CAN_DATA_LENGTH,
			                                                        serverInternalControlFunction,
			                                                        destination,
			                                                        get_priority());
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_button_activation_message(KeyActivationCode activationCode, std::uint16_t objectId, std::uint16_t parentObjectId, std::uint8_t keyNumber, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			std::array<std::uint8_t, CAN_DATA_LENGTH> buffer;

			buffer[0] = static_cast<std::uint8_t>(Function::ButtonActivationMessage);
			buffer[1] = static_cast<std::uint8_t>(activationCode);
			buffer[2] = get_low_byte(objectId);
			buffer[3] = get_high_byte(objectId);
			buffer[4] = get_low_byte(parentObjectId);
			buffer[5] = get_high_byte(parentObjectId);
			buffer[6] = keyNumber;
			buffer[7] = next_transaction_byte(destination);

			retVal = send_tracked_activation(buffer.data(), CAN_DATA_LENGTH, destination, 7);
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_user_layout_message(std::uint16_t firstId, bool firstShown, std::uint16_t secondId, bool secondShown, std::shared_ptr<ControlFunction> destination) const
	{
		if (get_version() < VTVersion::Version4) return false;
		const std::array<std::uint8_t, 8> data{9, get_low_byte(firstId), get_high_byte(firstId),
		  static_cast<std::uint8_t>(firstId != NULL_OBJECT_ID && firstShown), get_low_byte(secondId), get_high_byte(secondId),
		  static_cast<std::uint8_t>(secondId != NULL_OBJECT_ID && secondShown), next_transaction_byte(destination)};
		return send_tracked_activation(data.data(), data.size(), destination, 7);
	}

	bool VirtualTerminalServer::send_escape_message(std::uint16_t objectId, std::shared_ptr<ControlFunction> destination) const
	{
		const std::array<std::uint8_t, 8> data{4, get_low_byte(objectId), get_high_byte(objectId), 0, 0xFF, 0xFF, 0xFF, next_transaction_byte(destination)};
		return send_tracked_activation(data.data(), data.size(), destination, 7);
	}

	bool VirtualTerminalServer::send_change_numeric_value_message(std::uint16_t objectId, std::uint32_t value, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = {
				static_cast<std::uint8_t>(Function::VTChangeNumericValueMessage),
				get_low_byte(objectId),
				get_high_byte(objectId),
				next_transaction_byte(destination),
				get_byte(value, 0),
				get_byte(value, 1),
				get_byte(value, 2),
				get_byte(value, 3)
			};

			retVal = send_tracked_activation(buffer.data(), CAN_DATA_LENGTH, destination, 3);
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_select_input_object_message(std::uint16_t objectId, bool isObjectSelected, bool isObjectOpenForInput, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = {
				static_cast<std::uint8_t>(Function::VTSelectInputObjectMessage),
				get_low_byte(objectId),
				get_high_byte(objectId),
				static_cast<std::uint8_t>(isObjectSelected),
                [&]() -> std::uint8_t {
                    const auto ws = std::find_if(managedWorkingSetList.begin(), managedWorkingSetList.end(),
                        [&destination](const auto &candidate) {
                            return candidate && candidate->get_control_function() &&
                                candidate->get_control_function()->get_NAME().get_full_name() ==
                                    destination->get_NAME().get_full_name();
                        });
                    return ws != managedWorkingSetList.end() && (*ws)->get_version() < 4
                        ? 0xFF : static_cast<std::uint8_t>(isObjectOpenForInput);
                }(),
				0xFF,
				0xFF,
				next_transaction_byte(destination)
			};

			retVal = send_tracked_activation(buffer.data(), CAN_DATA_LENGTH, destination, 7);
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_soft_key_activation_message(KeyActivationCode activationCode, std::uint16_t objectId, std::uint16_t parentObjectId, std::uint8_t keyNumber, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = {
				static_cast<std::uint8_t>(Function::SoftKeyActivationMessage),
				static_cast<std::uint8_t>(activationCode),
				get_low_byte(objectId),
				get_high_byte(objectId),
				get_low_byte(parentObjectId),
				get_high_byte(parentObjectId),
				keyNumber,
				next_transaction_byte(destination)
			};

			retVal = send_tracked_activation(buffer.data(), CAN_DATA_LENGTH, destination, 7);
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_change_string_value_message(std::uint16_t objectId, const std::string &value, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			if (value.length() > 255)
			{
				LOG_WARNING("[VT Server] Truncated user input string value to the maximum of 255. The string was: " + value);
			}

			std::vector<std::uint8_t> buffer = {
				static_cast<std::uint8_t>(Function::VTChangeStringValueMessage),
				get_low_byte(objectId),
				get_high_byte(objectId),
				static_cast<std::uint8_t>(value.length() > 255 ? 255 : value.length())
			};

			for (std::uint16_t i = 0; i < value.length() && i < 255; i++)
			{
				buffer.push_back(static_cast<std::uint8_t>(value.at(i)));
			}

			while (buffer.size() < CAN_DATA_LENGTH)
			{
				buffer.push_back(0xFF); // The standard specifies the message must be padded to 8 bytes
			}

			retVal = send_tracked_activation(buffer.data(), static_cast<std::uint32_t>(buffer.size()), destination, 0xFF);
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_load_version_response(std::uint8_t errorCodes, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = {
				static_cast<std::uint8_t>(Function::LoadVersionCommand),
				0xFF, // Reserved
				0xFF, // Reserved
				0xFF, // Reserved
				0xFF, // Reserved
				errorCodes,
				0xFF, // Reserved
				0xFF // Reserved
			};
			retVal = CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
			                                                        buffer.data(),
			                                                        CAN_DATA_LENGTH,
			                                                        serverInternalControlFunction,
			                                                        destination,
			                                                        get_priority());
		}
		return retVal;
	}

	void VirtualTerminalServer::process_macro(std::shared_ptr<isobus::VTObject> object, isobus::EventID macroEvent, isobus::VirtualTerminalObjectType targetObjectType, std::shared_ptr<isobus::VirtualTerminalServerManagedWorkingSet> workingset)
	{
		if (nullptr != object && targetObjectType == object->get_object_type())
		{
			for (std::uint8_t i = 0; i < object->get_number_macros(); i++)
			{
				auto macroMetadata = object->get_macro(i);
				if (macroMetadata.event == macroEvent)
				{
					execute_macro(macroMetadata.macroID, workingset);
				}
			}
		}
	}

	bool VirtualTerminalServer::send_change_numeric_value_response(std::uint16_t objectID, std::uint8_t errorBitfield, std::uint32_t value, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			std::array<std::uint8_t, CAN_DATA_LENGTH> buffer;

			buffer[0] = static_cast<std::uint8_t>(Function::ChangeNumericValueCommand);
			buffer[1] = get_low_byte(objectID);
			buffer[2] = get_high_byte(objectID);
			buffer[3] = errorBitfield;
			buffer[4] = get_byte(value, 0);
			buffer[5] = get_byte(value, 1);
			buffer[6] = get_byte(value, 2);
			buffer[7] = get_byte(value, 3);

			retVal = CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
			                                                        buffer.data(),
			                                                        CAN_DATA_LENGTH,
			                                                        serverInternalControlFunction,
			                                                        destination,
			                                                        get_priority());
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_change_polygon_point_response(std::uint16_t objectID, std::uint8_t errorBitfield, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			std::array<std::uint8_t, CAN_DATA_LENGTH> buffer;

			buffer[0] = static_cast<std::uint8_t>(Function::ChangePolygonPointCommand);
			buffer[1] = get_low_byte(objectID);
			buffer[2] = get_high_byte(objectID);
			buffer[3] = errorBitfield;
			buffer[4] = 0xFF;
			buffer[5] = 0xFF;
			buffer[6] = 0xFF;
			buffer[7] = 0xFF;

			retVal = CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
			                                                        buffer.data(),
			                                                        CAN_DATA_LENGTH,
			                                                        serverInternalControlFunction,
			                                                        destination,
			                                                        get_priority());
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_change_size_response(std::uint16_t objectID, std::uint8_t errorBitfield, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			const std::array<std::uint8_t, CAN_DATA_LENGTH> buffer{
				static_cast<std::uint8_t>(Function::ChangeSizeCommand),
				get_low_byte(objectID),
				get_high_byte(objectID),
				errorBitfield,
				0xFF,
				0xFF,
				0xFF,
				0xFF
			};

			retVal = CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
			                                                        buffer.data(),
			                                                        CAN_DATA_LENGTH,
			                                                        serverInternalControlFunction,
			                                                        destination,
			                                                        get_priority());
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_change_soft_key_mask_response(std::uint16_t objectID, std::uint16_t newObjectID, std::uint8_t errorBitfield, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			const std::array<std::uint8_t, CAN_DATA_LENGTH> buffer{
				static_cast<std::uint8_t>(Function::ChangeSoftKeyMaskCommand),
				get_low_byte(objectID),
				get_high_byte(objectID),
				get_low_byte(newObjectID),
				get_high_byte(newObjectID),
				errorBitfield,
				0xFF,
				0xFF
			};

			retVal = CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
			                                                        buffer.data(),
			                                                        CAN_DATA_LENGTH,
			                                                        serverInternalControlFunction,
			                                                        destination,
			                                                        get_priority());
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_change_string_value_response(std::uint16_t objectID, std::uint8_t errorBitfield, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			const std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = {
				static_cast<std::uint8_t>(Function::ChangeStringValueCommand),
				0xFF,
				0xFF,
				get_low_byte(objectID),
				get_high_byte(objectID),
				errorBitfield,
				0xFF,
				0xFF
			};
			retVal = CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
			                                                        buffer.data(),
			                                                        CAN_DATA_LENGTH,
			                                                        serverInternalControlFunction,
			                                                        destination,
			                                                        get_priority());
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_delete_version_response(std::uint8_t errorBitfield, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			const std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = {
				static_cast<std::uint8_t>(Function::DeleteVersionCommand),
				0xFF,
				0xFF,
				0xFF,
				0xFF,
				errorBitfield,
				0xFF,
				0xFF
			};
			retVal = CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
			                                                        buffer.data(),
			                                                        CAN_DATA_LENGTH,
			                                                        serverInternalControlFunction,
			                                                        destination,
			                                                        get_priority());
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_delete_object_pool_response(std::uint8_t errorBitfield, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			const std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = {
				static_cast<std::uint8_t>(Function::DeleteObjectPoolCommand),
				errorBitfield,
				0xFF,
				0xFF,
				0xFF,
				0xFF,
				0xFF,
				0xFF
			};
			retVal = CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
			                                                        buffer.data(),
			                                                        CAN_DATA_LENGTH,
			                                                        serverInternalControlFunction,
			                                                        destination,
			                                                        get_priority());
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_enable_disable_object_response(std::uint16_t objectID, std::uint8_t errorBitfield, bool value, std::shared_ptr<ControlFunction> destination) const
	{
		bool retVal = false;

		if (nullptr != destination)
		{
			std::array<std::uint8_t, CAN_DATA_LENGTH> buffer;

			buffer[0] = static_cast<std::uint8_t>(Function::EnableDisableObjectCommand);
			buffer[1] = get_low_byte(objectID);
			buffer[2] = get_high_byte(objectID);
			buffer[3] = value;
			buffer[4] = errorBitfield;
			buffer[5] = 0xFF;
			buffer[6] = 0xFF;
			buffer[7] = 0xFF;

			retVal = CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
			                                                        buffer.data(),
			                                                        CAN_DATA_LENGTH,
			                                                        serverInternalControlFunction,
			                                                        destination,
			                                                        get_priority());
		}
		return retVal;
	}

	bool VirtualTerminalServer::send_end_of_object_pool_response(bool success,
	                                                             std::uint16_t parentIDOfFaultingObject,
	                                                             std::uint16_t faultingObjectID,
	                                                             std::uint8_t errorCodes,
	                                                             std::shared_ptr<ControlFunction> destination) const
	{
		std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = { 0 };

		buffer[0] = static_cast<std::uint8_t>(Function::EndOfObjectPoolMessage);
		buffer[1] = (success ? 0x00 : 0x01); // Error in object pool is 0x01, no error is 0x00
		buffer[2] = get_low_byte(parentIDOfFaultingObject);
		buffer[3] = get_high_byte(parentIDOfFaultingObject);
		buffer[4] = get_low_byte(faultingObjectID);
		buffer[5] = get_high_byte(faultingObjectID);
		buffer[6] = errorCodes;
		buffer[7] = 0xFF; // Reserved

		return CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
		                                                      buffer.data(),
		                                                      CAN_DATA_LENGTH,
		                                                      serverInternalControlFunction,
		                                                      destination,
		                                                      get_priority());
	}

	bool VirtualTerminalServer::send_execute_macro_or_extended_macro_response(std::uint16_t objectID, std::uint8_t errorBitfield, std::shared_ptr<ControlFunction> destination, bool extendedMacro) const
	{
		std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = { 0 };

		if (extendedMacro)
		{
			buffer[0] = static_cast<std::uint8_t>(Function::ExecuteExtendedMacroCommand);
		}
		else
		{
			buffer[0] = static_cast<std::uint8_t>(Function::ExecuteMacroCommand);
		}

		buffer[1] = get_low_byte(objectID);

		if (extendedMacro)
		{
			buffer[2] = get_high_byte(objectID);
		}
		else
		{
			buffer[2] = 0xFF;
		}

		buffer[3] = errorBitfield;
		buffer[4] = 0xFF;
		buffer[5] = 0xFF;
		buffer[6] = 0xFF;
		buffer[7] = 0xFF;

		return CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
		                                                      buffer.data(),
		                                                      CAN_DATA_LENGTH,
		                                                      serverInternalControlFunction,
		                                                      destination,
		                                                      get_priority());
	}

	bool VirtualTerminalServer::send_hide_show_object_response(std::uint16_t objectID, std::uint8_t errorBitfield, bool value, std::shared_ptr<ControlFunction> destination) const
	{
		std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = { 0 };

		buffer[0] = static_cast<std::uint8_t>(Function::HideShowObjectCommand);
		buffer[1] = get_low_byte(objectID);
		buffer[2] = get_high_byte(objectID);
		buffer[3] = static_cast<std::uint8_t>(value);
		buffer[4] = errorBitfield;
		buffer[5] = 0xFF; // Reserved
		buffer[6] = 0xFF; // Reserved
		buffer[7] = 0xFF; // Reserved

		return CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
		                                                      buffer.data(),
		                                                      CAN_DATA_LENGTH,
		                                                      serverInternalControlFunction,
		                                                      destination,
		                                                      get_priority());
	}

	bool VirtualTerminalServer::send_change_priority_response(std::uint16_t objectID, std::uint8_t errorBitfield, std::uint8_t priority, std::shared_ptr<ControlFunction> destination) const
	{
		std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = { 0 };

		buffer[0] = static_cast<std::uint8_t>(Function::ChangePriorityCommand);
		buffer[1] = get_low_byte(objectID);
		buffer[2] = get_high_byte(objectID);
		buffer[3] = priority;
		buffer[4] = errorBitfield;
		buffer[5] = 0xFF; // Reserved
		buffer[6] = 0xFF; // Reserved
		buffer[7] = 0xFF; // Reserved

		return CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
		                                                      buffer.data(),
		                                                      CAN_DATA_LENGTH,
		                                                      serverInternalControlFunction,
		                                                      destination,
		                                                      get_priority());
	}

	bool VirtualTerminalServer::send_select_input_object_response(std::uint16_t objectID, std::uint8_t errorBitfield, SelectInputObjectResponse response, std::shared_ptr<ControlFunction> destination) const
	{
		std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = { 0 };

		buffer[0] = static_cast<std::uint8_t>(Function::SelectInputObjectCommand);
		buffer[1] = get_low_byte(objectID);
		buffer[2] = get_high_byte(objectID);
		buffer[3] = static_cast<std::uint8_t>(response);
		buffer[4] = errorBitfield;
		buffer[5] = 0xFF; // Reserved
		buffer[6] = 0xFF; // Reserved
		buffer[7] = 0xFF; // Reserved

		return CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
		                                                      buffer.data(),
		                                                      CAN_DATA_LENGTH,
		                                                      serverInternalControlFunction,
		                                                      destination,
		                                                      get_priority());
	}

	bool VirtualTerminalServer::send_esc_response(std::uint16_t objectID, std::uint8_t errorBitfield, std::shared_ptr<ControlFunction> destination) const
	{
		std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = {
		  static_cast<std::uint8_t>(Function::ESCCommand),
		  static_cast<std::uint8_t>(objectID & 0xFF),
		  static_cast<std::uint8_t>(objectID >> 8),
		  errorBitfield,
		  0xFF, 0xFF, 0xFF, 0xFF
		};
		return CANNetworkManager::CANNetwork.send_can_message(
		  static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
		  buffer.data(), buffer.size(), serverInternalControlFunction, destination, get_priority());
	}

	bool VirtualTerminalServer::send_status_message() const
	{
		std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = { 0 };

		buffer[0] = static_cast<std::uint8_t>(Function::VTStatusMessage);
		buffer[1] = activeWorkingSetMasterAddress;
		buffer[2] = get_low_byte(activeWorkingSetDataMaskObjectID);
		buffer[3] = get_high_byte(activeWorkingSetDataMaskObjectID);
		buffer[4] = get_low_byte(activeWorkingSetSoftkeyMaskObjectID);
		buffer[5] = get_high_byte(activeWorkingSetSoftkeyMaskObjectID);
		buffer[6] = busyCodesBitfield;
		buffer[7] = currentCommandFunctionCode;
		return CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
		                                                      buffer.data(),
		                                                      CAN_DATA_LENGTH,
		                                                      serverInternalControlFunction,
		                                                      nullptr,
		                                                      get_priority());
	}

	bool VirtualTerminalServer::send_supported_objects(std::shared_ptr<ControlFunction> destination) const
	{
		auto supportedObjects = get_supported_objects();
		std::vector<std::uint8_t> buffer = { static_cast<std::uint8_t>(Function::GetSupportedObjectsMessage),
			                                   static_cast<std::uint8_t>(supportedObjects.size()) };

		for (const auto &supportedObject : supportedObjects)
		{
			buffer.push_back(supportedObject);
		}
		return CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
		                                                      buffer.data(),
		                                                      static_cast<std::uint32_t>(buffer.size()),
		                                                      serverInternalControlFunction,
		                                                      destination,
		                                                      get_priority());
	}

	bool VirtualTerminalServer::send_audio_signal_response(std::uint8_t errorBitfield, std::shared_ptr<ControlFunction> destination) const
	{
		std::vector<std::uint8_t> buffer = { static_cast<std::uint8_t>(Function::ControlAudioSignalCommand), errorBitfield, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
		return CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
		                                                      buffer.data(),
		                                                      CAN_DATA_LENGTH,
		                                                      serverInternalControlFunction,
		                                                      destination,
		                                                      get_priority());
	}

	bool VirtualTerminalServer::send_get_window_mask_data_response(std::shared_ptr<ControlFunction> destination) const
	{
		std::array<std::uint8_t, CAN_DATA_LENGTH> buffer = { 0 };

		buffer[0] = static_cast<std::uint8_t>(Function::GetWindowMaskDataMessage);
		buffer[1] = get_user_layout_datamask_bg_color();
		buffer[2] = get_user_layout_softkeymask_bg_color();
		buffer[3] = 0xFF; // Reserved
		buffer[4] = 0xFF; // Reserved
		buffer[5] = 0xFF; // Reserved
		buffer[6] = 0xFF; // Reserved
		buffer[7] = 0xFF; // Reserved

		return CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
		                                                      buffer.data(),
		                                                      CAN_DATA_LENGTH,
		                                                      serverInternalControlFunction,
		                                                      destination,
		                                                      get_priority());
	}

	bool VirtualTerminalServer::send_audio_volume_response(std::uint8_t errorBitfield, std::shared_ptr<ControlFunction> destination) const
	{
		std::vector<std::uint8_t> buffer = { static_cast<std::uint8_t>(Function::SetAudioVolumeCommand), errorBitfield, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
		return CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
		                                                      buffer.data(),
		                                                      CAN_DATA_LENGTH,
		                                                      serverInternalControlFunction,
		                                                      destination,
		                                                      get_priority());
	}

	bool VirtualTerminalServer::send_auxiliary_capabilities_response(std::uint8_t requestType, std::shared_ptr<ControlFunction> destination) const
	{
		std::vector<AuxiliaryCapabilitiesUnit> units;
		if (requestType <= 1)
		{
			const auto requestedType = (0 == requestType)
			  ? VirtualTerminalObjectType::AuxiliaryInputType2
			  : VirtualTerminalObjectType::AuxiliaryFunctionType2;
			for (const auto &workingSet : managedWorkingSetList)
			{
				if (nullptr == workingSet->get_working_set_object())
					continue;
				std::map<std::uint16_t, std::uint8_t> groupedSets;
				const auto workingSetName = workingSet->get_control_function()->get_NAME().get_full_name();
				for (const auto &entry : workingSet->get_object_tree())
				{
					if ((nullptr == entry.second) || (requestedType != entry.second->get_object_type()))
						continue;
					std::uint32_t attributes = 0;
					if (entry.second->get_attribute(2, attributes))
					{
						const bool assigned = std::any_of(
						  managedAuxiliaryAssignments.begin(), managedAuxiliaryAssignments.end(),
						  [requestType, workingSetName, objectID = entry.first](const auto &assignment) {
							  if (AuxiliaryAssignmentState::Active != assignment.state)
								  return false;
							  return (0 == requestType)
							    ? ((assignment.assignment.inputUnitName == workingSetName) &&
							       (assignment.assignment.inputObjectID == objectID))
							    : ((assignment.functionWorkingSetName == workingSetName) &&
							       (assignment.assignment.functionObjectID == objectID));
						  });
						const std::uint8_t assignedAttributes = static_cast<std::uint8_t>(requestType | (assigned ? 0x02 : 0));
						const std::uint16_t key = static_cast<std::uint8_t>(attributes) |
						                          (static_cast<std::uint16_t>(assignedAttributes) << 8);
						auto &count = groupedSets[key];
						if (count < 0xFF)
							++count;
					}
				}
				if (groupedSets.empty() || (units.size() == 0xFF))
					continue;
				AuxiliaryCapabilitiesUnit unit;
				unit.name = workingSetName;
				for (const auto &set : groupedSets)
					unit.sets.push_back({ set.second, static_cast<std::uint8_t>(set.first), static_cast<std::uint8_t>(set.first >> 8) });
				units.push_back(std::move(unit));
			}
		}
		auto buffer = make_auxiliary_capabilities_response(requestType, units);
		return CANNetworkManager::CANNetwork.send_can_message(
		  static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
		  buffer.data(), buffer.size(), serverInternalControlFunction, destination, get_priority());
	}

	bool VirtualTerminalServer::send_preferred_assignment_response(
	  std::uint8_t errorBitfield, std::uint16_t faultingFunctionObjectID,
	  std::shared_ptr<ControlFunction> destination) const
	{
		const auto buffer = make_preferred_assignment_response(errorBitfield,
		                                                       faultingFunctionObjectID);
		return CANNetworkManager::CANNetwork.send_can_message(
		  static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
		  buffer.data(), buffer.size(), serverInternalControlFunction, destination, get_priority());
	}

	bool VirtualTerminalServer::send_auxiliary_input_enable_command(
	  std::uint16_t inputObjectID, bool enable, std::shared_ptr<ControlFunction> destination) const
	{
		const auto buffer = make_auxiliary_input_enable_command(inputObjectID, enable);
		return CANNetworkManager::CANNetwork.send_can_message(
		  static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
		  buffer.data(), buffer.size(), serverInternalControlFunction, destination, get_priority());
	}

	bool VirtualTerminalServer::send_auxiliary_assignment_command(
	  const PreferredAuxiliaryAssignment &assignment,
	  std::shared_ptr<ControlFunction> destination, bool remove) const
	{
		const auto buffer = make_auxiliary_assignment_command(assignment, remove);
		return CANNetworkManager::CANNetwork.send_can_message(
		  static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
		  buffer.data(), buffer.size(), serverInternalControlFunction, destination, get_priority());
	}

	std::array<std::uint8_t, CAN_DATA_LENGTH> VirtualTerminalServer::make_preferred_assignment_response(
	  std::uint8_t errorBitfield, std::uint16_t faultingFunctionObjectID)
	{
		return {
		  static_cast<std::uint8_t>(Function::PreferredAssignmentCommand),
		  errorBitfield,
		  get_low_byte(faultingFunctionObjectID),
		  get_high_byte(faultingFunctionObjectID),
		  0xFF, 0xFF, 0xFF, 0xFF
		};
	}

	std::array<std::uint8_t, CAN_DATA_LENGTH> VirtualTerminalServer::make_auxiliary_input_enable_command(
	  std::uint16_t inputObjectID, bool enable)
	{
		return {
		  static_cast<std::uint8_t>(Function::AuxiliaryInputStatusTypeTwoEnableCommand),
		  get_low_byte(inputObjectID), get_high_byte(inputObjectID),
		  static_cast<std::uint8_t>(enable), 0xFF, 0xFF, 0xFF, 0xFF
		};
	}

	std::array<std::uint8_t, 14> VirtualTerminalServer::make_auxiliary_assignment_command(
	  const PreferredAuxiliaryAssignment &assignment, bool remove)
	{
		std::array<std::uint8_t, 14> buffer{};
		buffer[0] = static_cast<std::uint8_t>(Function::AuxiliaryAssignmentTypeTwoCommand);
		const auto inputName = remove ? std::numeric_limits<std::uint64_t>::max() : assignment.inputUnitName;
		for (std::uint8_t byte = 0; byte < 8; ++byte)
			buffer[1 + byte] = static_cast<std::uint8_t>(inputName >> (8 * byte));
		buffer[9] = remove ? 0x9F : static_cast<std::uint8_t>(0x80 | assignment.functionType);
		const auto inputObjectID = remove ? NULL_OBJECT_ID : assignment.inputObjectID;
		buffer[10] = get_low_byte(inputObjectID);
		buffer[11] = get_high_byte(inputObjectID);
		buffer[12] = get_low_byte(assignment.functionObjectID);
		buffer[13] = get_high_byte(assignment.functionObjectID);
		return buffer;
	}

	void VirtualTerminalServer::update_auxiliary_assignments()
	{
		const auto findWorkingSet = [this](std::uint64_t name) {
			return std::find_if(managedWorkingSetList.begin(), managedWorkingSetList.end(),
			                    [name](const auto &workingSet) {
				                    return workingSet->get_control_function()->get_NAME().get_full_name() == name;
			                    });
		};
		for (auto &managed : managedAuxiliaryAssignments)
		{
			if ((AuxiliaryAssignmentState::Active == managed.state) &&
			    ([&]() {
				    const auto input = findWorkingSet(managed.assignment.inputUnitName);
				    return (input == managedWorkingSetList.end()) ||
				           ((*input)->get_auxiliary_input_status() != 1) ||
				           SystemTiming::time_expired_ms((*input)->get_auxiliary_input_maintenance_timestamp_ms(), 300);
			    })())
			{
				managed.state = AuxiliaryAssignmentState::PendingRemoval;
				managed.attempts = 0;
			}

			const bool waiting = (AuxiliaryAssignmentState::WaitingEnableResponse == managed.state) ||
			                     (AuxiliaryAssignmentState::WaitingAssignmentResponse == managed.state) ||
			                     (AuxiliaryAssignmentState::WaitingRemovalResponse == managed.state) ||
			                     (AuxiliaryAssignmentState::WaitingDisableResponse == managed.state);
			if (waiting && !SystemTiming::time_expired_ms(managed.lastCommandTimestampMs, 2000))
				continue;
			if (waiting)
			{
				if (managed.attempts >= 3)
				{
					managed.state = AuxiliaryAssignmentState::Failed;
					continue;
				}
				if (AuxiliaryAssignmentState::WaitingEnableResponse == managed.state)
					managed.state = AuxiliaryAssignmentState::PendingEnable;
				else if (AuxiliaryAssignmentState::WaitingDisableResponse == managed.state)
					managed.state = AuxiliaryAssignmentState::PendingDisable;
				else if (AuxiliaryAssignmentState::WaitingAssignmentResponse == managed.state)
					managed.state = AuxiliaryAssignmentState::PendingAssignment;
				else
					managed.state = AuxiliaryAssignmentState::PendingRemoval;
			}

			if ((AuxiliaryAssignmentState::PendingEnable == managed.state) ||
			    (AuxiliaryAssignmentState::PendingDisable == managed.state))
			{
				const bool disabling = AuxiliaryAssignmentState::PendingDisable == managed.state;
				const bool inputAlreadyEnabled = !disabling && std::any_of(
				  managedAuxiliaryAssignments.begin(), managedAuxiliaryAssignments.end(),
				  [&managed](const auto &other) {
					  return (&other != &managed) &&
					         (other.assignment.inputUnitName == managed.assignment.inputUnitName) &&
					         (other.assignment.inputObjectID == managed.assignment.inputObjectID) &&
					         ((AuxiliaryAssignmentState::PendingAssignment == other.state) ||
					          (AuxiliaryAssignmentState::WaitingAssignmentResponse == other.state) ||
					          (AuxiliaryAssignmentState::Active == other.state) ||
					          (AuxiliaryAssignmentState::PendingRemoval == other.state) ||
					          (AuxiliaryAssignmentState::WaitingRemovalResponse == other.state));
				  });
				if (inputAlreadyEnabled)
				{
					managed.state = AuxiliaryAssignmentState::PendingAssignment;
					managed.attempts = 0;
					continue;
				}
				const bool priorRemovalInFlight = !disabling && std::any_of(
				  managedAuxiliaryAssignments.begin(), managedAuxiliaryAssignments.end(),
				  [&managed](const auto &other) {
					  return (&other != &managed) &&
					         (other.functionWorkingSetName == managed.functionWorkingSetName) &&
					         ((AuxiliaryAssignmentState::PendingRemoval == other.state) ||
					          (AuxiliaryAssignmentState::WaitingRemovalResponse == other.state) ||
					          (AuxiliaryAssignmentState::PendingDisable == other.state) ||
					          (AuxiliaryAssignmentState::WaitingDisableResponse == other.state));
				  });
				if (priorRemovalInFlight)
					continue;
				const bool enableInFlight = std::any_of(
				  managedAuxiliaryAssignments.begin(), managedAuxiliaryAssignments.end(),
				  [&managed](const auto &other) {
					  return (&other != &managed) &&
					         (other.assignment.inputUnitName == managed.assignment.inputUnitName) &&
					         (other.assignment.inputObjectID == managed.assignment.inputObjectID) &&
					         ((AuxiliaryAssignmentState::WaitingEnableResponse == other.state) ||
					          (AuxiliaryAssignmentState::WaitingDisableResponse == other.state));
				  });
				if (enableInFlight)
					continue;
				const auto input = findWorkingSet(managed.assignment.inputUnitName);
				if ((input != managedWorkingSetList.end()) &&
				    send_auxiliary_input_enable_command(managed.assignment.inputObjectID, !disabling,
				                                        (*input)->get_control_function()))
				{
					managed.state = disabling ? AuxiliaryAssignmentState::WaitingDisableResponse
					                           : AuxiliaryAssignmentState::WaitingEnableResponse;
					++managed.attempts;
					managed.lastCommandTimestampMs = SystemTiming::get_timestamp_ms();
				}
			}
			else if ((AuxiliaryAssignmentState::PendingAssignment == managed.state) ||
			         (AuxiliaryAssignmentState::PendingRemoval == managed.state))
			{
				const bool removal = AuxiliaryAssignmentState::PendingRemoval == managed.state;
				const bool anotherPending = std::any_of(
				  managedAuxiliaryAssignments.begin(), managedAuxiliaryAssignments.end(),
				  [&managed](const auto &other) {
					  return (&other != &managed) &&
					         (other.functionWorkingSetName == managed.functionWorkingSetName) &&
					         ((AuxiliaryAssignmentState::WaitingAssignmentResponse == other.state) ||
					          (AuxiliaryAssignmentState::WaitingRemovalResponse == other.state));
				  });
				const auto function = findWorkingSet(managed.functionWorkingSetName);
				if (!anotherPending && (function != managedWorkingSetList.end()) &&
				    send_auxiliary_assignment_command(managed.assignment,
				                                      (*function)->get_control_function(), removal))
				{
					managed.state = removal ? AuxiliaryAssignmentState::WaitingRemovalResponse
					                        : AuxiliaryAssignmentState::WaitingAssignmentResponse;
					++managed.attempts;
					managed.lastCommandTimestampMs = SystemTiming::get_timestamp_ms();
				}
			}
		}
	}

	void VirtualTerminalServer::suspend_auxiliary_assignments_for_working_set(std::uint64_t workingSetName)
	{
		preferredAuxiliaryAssignments.erase(workingSetName);
		for (auto &managed : managedAuxiliaryAssignments)
		{
			if (managed.assignment.inputUnitName == workingSetName)
			{
				managed.state = AuxiliaryAssignmentState::PendingRemoval;
				managed.attempts = 0;
			}
			else if (managed.functionWorkingSetName == workingSetName)
			{
				managed.state = AuxiliaryAssignmentState::PendingDisable;
				managed.attempts = 0;
			}
		}
	}

	std::vector<std::uint8_t> VirtualTerminalServer::make_auxiliary_capabilities_response(
	  std::uint8_t requestType, const std::vector<AuxiliaryCapabilitiesUnit> &units)
	{
		std::vector<std::uint8_t> buffer = {
		  static_cast<std::uint8_t>(Function::AuxiliaryCapabilitiesRequest), 0
		};
		if (requestType > 1)
			return buffer;
		buffer[1] = static_cast<std::uint8_t>(std::min<std::size_t>(units.size(), 0xFF));
		for (std::size_t index = 0; index < buffer[1]; ++index)
		{
			const auto &unit = units[index];
			for (std::uint8_t byte = 0; byte < 8; ++byte)
				buffer.push_back(static_cast<std::uint8_t>(unit.name >> (8 * byte)));
			buffer.push_back(static_cast<std::uint8_t>(std::min<std::size_t>(unit.sets.size(), 0xFF)));
			std::size_t setIndex = 0;
			for (const auto &set : unit.sets)
			{
				if (setIndex++ == 0xFF)
					break;
				buffer.push_back(set.numberOfInstances);
				buffer.push_back(set.functionAttributes);
				buffer.push_back(set.assignedAttributes);
			}
		}
		return buffer;
	}

	VirtualTerminalServer::PreferredAuxiliaryAssignmentParseResult
	VirtualTerminalServer::parse_preferred_auxiliary_assignment(const std::vector<std::uint8_t> &messageData)
	{
		PreferredAuxiliaryAssignmentParseResult result;
		if ((messageData.size() < 2) ||
		    (messageData[0] != static_cast<std::uint8_t>(Function::PreferredAssignmentCommand)))
		{
			result.errorBitfield = 0x10;
			return result;
		}

		std::size_t offset = 2;
		std::set<std::uint16_t> functionIDs;
		for (std::uint16_t unitIndex = 0; unitIndex < messageData[1]; ++unitIndex)
		{
			if ((offset + 11) > messageData.size())
			{
				result.errorBitfield |= 0x10;
				return result;
			}
			std::uint64_t inputName = 0;
			for (std::uint8_t byte = 0; byte < 8; ++byte)
				inputName |= static_cast<std::uint64_t>(messageData[offset + byte]) << (8 * byte);
			offset += 8;
			const auto model = static_cast<std::uint16_t>(messageData[offset]) |
			                   (static_cast<std::uint16_t>(messageData[offset + 1]) << 8);
			offset += 2;
			const auto numberOfFunctions = messageData[offset++];
			if ((offset + (static_cast<std::size_t>(numberOfFunctions) * 4)) > messageData.size())
			{
				result.errorBitfield |= 0x10;
				return result;
			}
			for (std::uint16_t functionIndex = 0; functionIndex < numberOfFunctions; ++functionIndex)
			{
				PreferredAuxiliaryAssignment assignment;
				assignment.inputUnitName = inputName;
				assignment.modelIdentificationCode = model;
				assignment.functionObjectID = static_cast<std::uint16_t>(messageData[offset]) |
				                              (static_cast<std::uint16_t>(messageData[offset + 1]) << 8);
				assignment.inputObjectID = static_cast<std::uint16_t>(messageData[offset + 2]) |
				                           (static_cast<std::uint16_t>(messageData[offset + 3]) << 8);
				offset += 4;
				if (!functionIDs.insert(assignment.functionObjectID).second)
				{
					result.errorBitfield |= 0x08;
					if (NULL_OBJECT_ID == result.faultingFunctionObjectID)
						result.faultingFunctionObjectID = assignment.functionObjectID;
				}
				result.assignments.push_back(assignment);
			}
		}

		for (; offset < messageData.size(); ++offset)
		{
			if (0xFF != messageData[offset])
			{
				result.errorBitfield |= 0x10;
				break;
			}
		}
		return result;
	}

	bool VirtualTerminalServer::send_capture_screen_response(std::uint8_t item, std::uint8_t path, std::uint8_t errorCode, std::uint16_t imageId, std::shared_ptr<ControlFunction> requestor) const
	{
		const auto buffer = make_screen_capture_response(item, path, errorCode, imageId);
		return CANNetworkManager::CANNetwork.send_can_message(static_cast<std::uint32_t>(CANLibParameterGroupNumber::VirtualTerminalToECU),
		                                                      buffer.data(),
		                                                      CAN_DATA_LENGTH,
		                                                      serverInternalControlFunction,
		                                                      requestor,
		                                                      get_priority());
	}

	void VirtualTerminalServer::update()
	{
		update_auxiliary_assignments();
		update_activation_transactions();
		if ((isobus::SystemTiming::time_expired_ms(statusMessageTimestamp_ms, 1000)) &&
		    (send_status_message()))
		{
			statusMessageTimestamp_ms = isobus::SystemTiming::get_timestamp_ms();
		}

		for (const auto &ws : managedWorkingSetList)
		{
			if (VirtualTerminalServerManagedWorkingSet::ObjectPoolProcessingThreadState::Success == ws->get_object_pool_processing_state())
			{
				ws->join_parsing_thread();
				if (ws->get_was_object_pool_loaded_from_non_volatile_memory())
				{
					const auto function = ws->get_pending_load_version_response_function();
					if (function == static_cast<std::uint8_t>(Function::ExtendedLoadVersionCommand))
						send_extended_version_response(function, 0, ws->get_control_function());
					else
						send_load_version_response(0, ws->get_control_function());
					ws->set_was_object_pool_loaded_from_non_volatile_memory(false, {});
					ws->set_pending_load_version_response_function(0, {});
				}
				else
				{
					send_end_of_object_pool_response(true, NULL_OBJECT_ID, NULL_OBJECT_ID, 0, ws->get_control_function());
				}
				if (isobus::NULL_CAN_ADDRESS == activeWorkingSetMasterAddress)
				{
					activeWorkingSetMasterAddress = ws->get_control_function()->get_address();
					activeWorkingSetDataMaskObjectID = std::static_pointer_cast<WorkingSet>(ws->get_working_set_object())->get_active_mask();
				}
			}
			else if (VirtualTerminalServerManagedWorkingSet::ObjectPoolProcessingThreadState::Fail == ws->get_object_pool_processing_state())
			{
				ws->join_parsing_thread();
				if (ws->get_was_object_pool_loaded_from_non_volatile_memory())
				{
					const auto function = ws->get_pending_load_version_response_function();
					if (function == static_cast<std::uint8_t>(Function::ExtendedLoadVersionCommand))
						send_extended_version_response(function, 0x01, ws->get_control_function());
					else
						send_load_version_response(0x01, ws->get_control_function());
					ws->set_was_object_pool_loaded_from_non_volatile_memory(false, {});
					ws->set_pending_load_version_response_function(0, {});
				}
				else
				{
					///  @todo Get the parent object ID of the faulting object
					send_end_of_object_pool_response(false, NULL_OBJECT_ID, ws->get_object_pool_faulting_object_id(), 0x04, ws->get_control_function());
				}
			}
		}
	}
}
