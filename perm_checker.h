/*

Permission checker.

Copyright (C) 2017 Sergey Kolevatov

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

// $Revision: 13604 $ $Date:: 2020-09-02 #$ $Author: serge $

#ifndef GENERIC_HANDLER_PERM_CHECKER_H
#define GENERIC_HANDLER_PERM_CHECKER_H

#include "session_manager/types.h"      // session_manager::user_id_t
#include "basic_parser/object.h"

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

class PermChecker
{
public:

    PermChecker();

    bool init(
            session_manager::Manager            * sess_man );

    bool is_authenticated( session_manager::user_id_t * session_user_id, const basic_parser::Object * r );
    bool is_allowed( session_manager::user_id_t session_user_id, const basic_parser::Object * r );

private:
    bool is_allowed_AuthenticateRequest( session_manager::user_id_t session_user_id, const basic_parser::Object * r );
    bool is_allowed_AuthenticateAltRequest( session_manager::user_id_t session_user_id, const basic_parser::Object * r );
    bool is_allowed_CloseSessionRequest( session_manager::user_id_t session_user_id, const basic_parser::Object * r );
    bool is_allowed_GetUserIdRequest( session_manager::user_id_t session_user_id, const basic_parser::Object * r );
    bool is_allowed_GetSessionInfoRequest( session_manager::user_id_t session_user_id, const basic_parser::Object * r );

private:
    session_manager::Manager            * sess_man_;

};

} // namespace generic_handler

#endif // GENERIC_HANDLER_PERM_CHECKER_H
