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

// $Revision: 8863 $ $Date:: 2018-03-28 #$ $Author: serge $

#ifndef GENERIC_HANDLER_HANDLER_H
#define GENERIC_HANDLER_HANDLER_H

#include <mutex>                    // std::mutex

#include "session_manager/types.h"      // session_manager::user_id_t

namespace generic_protocol
{
class ForwardMessage;
class BackwardMessage;
}

namespace session_manager
{
class Manager;
}

namespace generic_handler
{

class Handler
{
public:

    Handler();

    bool init(
            session_manager::Manager    * sess_man );

    generic_protocol::BackwardMessage* handle( session_manager::user_id_t session_user_id, const generic_protocol::ForwardMessage * r );

private:

    generic_protocol::BackwardMessage* handle_AuthenticateRequest( session_manager::user_id_t session_user_id, const generic_protocol::ForwardMessage * r );
    generic_protocol::BackwardMessage* handle_AuthenticateAltRequest( session_manager::user_id_t session_user_id, const generic_protocol::ForwardMessage * r );
    generic_protocol::BackwardMessage* handle_CloseSessionRequest( session_manager::user_id_t session_user_id, const generic_protocol::ForwardMessage * r );
    generic_protocol::BackwardMessage* handle_GetUserIdRequest( session_manager::user_id_t session_user_id, const generic_protocol::ForwardMessage * r );
    generic_protocol::BackwardMessage* handle_GetSessionInfoRequest( session_manager::user_id_t session_user_id, const generic_protocol::ForwardMessage * r );

private:
    mutable std::mutex          mutex_;

    session_manager::Manager    * sess_man_;
};

} // namespace generic_handler

#endif // GENERIC_HANDLER_HANDLER_H
