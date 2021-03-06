/*

Generic request handler.

Copyright (C) 2016 Sergey Kolevatov

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

*/

// $Revision: 13922 $ $Date:: 2020-10-03 #$ $Author: serge $

#ifndef GENERIC_HANDLER_HANDLER_H
#define GENERIC_HANDLER_HANDLER_H

#include <mutex>                    // std::mutex

#include "session_manager/types.h"      // session_manager::user_id_t
#include "user_manager/i_id_converter.h"    // user_manager::IIdConverter
#include "basic_parser/object.h"

namespace generic_protocol
{
class ForwardMessage;
class BackwardMessage;
}

namespace session_manager
{
class SessionManager;
}

namespace generic_handler
{

class Handler
{
public:

    Handler();

    bool init(
            session_manager::SessionManager    * sess_man,
            user_manager::IIdConverter  * user_man );

    generic_protocol::BackwardMessage* handle( session_manager::user_id_t session_user_id, const basic_parser::Object * r );

private:

    generic_protocol::BackwardMessage* handle_AuthenticateRequest( session_manager::user_id_t session_user_id, const basic_parser::Object * r );
    generic_protocol::BackwardMessage* handle_AuthenticateAltRequest( session_manager::user_id_t session_user_id, const basic_parser::Object * r );
    generic_protocol::BackwardMessage* handle_CloseSessionRequest( session_manager::user_id_t session_user_id, const basic_parser::Object * r );
    generic_protocol::BackwardMessage* handle_GetUserIdRequest( session_manager::user_id_t session_user_id, const basic_parser::Object * r );
    generic_protocol::BackwardMessage* handle_GetSessionInfoRequest( session_manager::user_id_t session_user_id, const basic_parser::Object * r );

private:
    mutable std::mutex          mutex_;

    session_manager::SessionManager    * sess_man_;
    user_manager::IIdConverter  * user_man_;
};

} // namespace generic_handler

#endif // GENERIC_HANDLER_HANDLER_H
