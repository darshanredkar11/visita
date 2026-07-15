package app.visitorpass.db

import kotlin.Long
import kotlin.String

public data class Entry_log(
  public val id: String,
  public val pass_id: String,
  public val action: String,
  public val occurred_at: String,
  public val synced: Long,
  public val denial_reason: String?,
  public val guard_note: String?,
)
