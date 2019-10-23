/*
 * Copyright (c) 2015-2019, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.sdk.common;

import java.util.concurrent.TimeUnit;

/**
 * The {@link TimeSpan} class is implemented to simplify work with time spans. You can easily
 * specify the time span for 5 min for example.
 */
public final class TimeSpan {

  private long lifetime;
  private TimeUnit timeUnit;

  /**
   * Represents time span (interval) in specified time unit.
   *
   * @param lifetime in specified by second argument unit. Must be &gt;= 0.
   * @param timeUnit any {@link TimeUnit}.
   * @return TimeSpan instance with time span in specified unit.
   */
  public static TimeSpan fromTime(long lifetime, TimeUnit timeUnit) {
    if (lifetime <= 0) {
      throw new IllegalArgumentException("Value of 'lifetime' should be more that zero (0)");
    }

    return new TimeSpan(lifetime, timeUnit);
  }

  private TimeSpan(long lifetime, TimeUnit timeUnit) {
    this.lifetime = lifetime;
    this.timeUnit = timeUnit;
  }

  /**
   * If TimeSpan was cleared - time span will be added to zero (0) value.
   *
   * @param increment the milliseconds to be added to current time. Must be &gt;= 0.
   */
  public void add(long increment) {
    if (increment <= 0) {
      throw new IllegalArgumentException("Value of 'increment' should be more that zero (0)");
    }

    this.lifetime += increment;
  }

  /**
   * Clears time span to zero (0) value.
   */
  public void clear() {
    lifetime = 0;
  }

  /**
   * Decrease the expire interval. Cannot be less than zero (0). (Ex. timeSpan.add(2);
   * timeSpan.decrease(5); timeSpan.getSpan(); output value is zero (0))
   *
   * @param decrement to decrease the expire interval. Must be &gt;= 0.
   */
  public void decrease(long decrement) {
    if (decrement <= 0) {
      throw new IllegalArgumentException("Value of 'decrement' should be more that zero (0)");
    }

    this.lifetime -= decrement;
  }

  /**
   * Get time span.
   *
   * @return Time Span in milliseconds.
   */
  public long getSpanMilliseconds() {
    return getSpanSeconds() * 1000;
  }

  /**
   * Get time span.
   *
   * @return Time Span in seconds.
   */
  public long getSpanSeconds() {
    if (lifetime == 0) {
      return 0;
    }

    switch (timeUnit) {
      case NANOSECONDS:
        return lifetime / 1000000000; // 1000000000 nanoseconds is 1 second
      case MICROSECONDS:
        return lifetime / 1000000; // 1000000 microseconds is 1 second
      case MILLISECONDS:
        return lifetime / 1000; // 1000 milliseconds is 1 second
      case SECONDS:
        return lifetime;
      case MINUTES:
        return lifetime * 60;
      case HOURS:
        return lifetime * 60 * 60;
      case DAYS:
        return lifetime * 24 * 60 * 60;
      default:
        return lifetime;
    }
  }
}
