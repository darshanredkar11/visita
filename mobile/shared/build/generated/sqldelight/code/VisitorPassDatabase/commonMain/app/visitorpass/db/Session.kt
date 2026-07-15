package app.visitorpass.db

import kotlin.Long
import kotlin.String

public data class Session(
  public val key: Long,
  public val token: String,
  public val role: String,
  public val org_id: String,
  public val unit_identifier: String,
  public val user_name: String,
)
