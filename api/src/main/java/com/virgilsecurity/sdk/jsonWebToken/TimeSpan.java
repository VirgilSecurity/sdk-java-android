package com.virgilsecurity.sdk.jsonWebToken;

import java.util.Date;
import java.util.concurrent.TimeUnit;

public class TimeSpan {

    private Date date;
    // TODO: 1/19/18 move to sdk package
    // TODO: 1/25/18 check if span works well on jwt.io

    /**
     * Represents time interval in specified time unit
     *
     * @param date of expire
     */
    public TimeSpan(Date date) {
        this.date = date;
    }

    /**
     * Represents time interval in specified time unit
     *
     * @param milliseconds to expire
     */
    public TimeSpan(long milliseconds) {
        this.date = new Date(milliseconds);
    }

    /**
     * @param time     in specified by second argument unit. Must be >= 0.
     * @param timeUnit supported TimeUnit: SECONDS, MINUTES, HOURS, DAYS.
     * @return TimeSpan instance with time span in specified unit.
     * For unsupported units time span in minutes will be returned.
     */
    public static TimeSpan fromTime(int time, TimeUnit timeUnit) {
        if (time <= 0)
            throw new IllegalArgumentException("Time should be more that zero (0)");

        long span = new Date().getTime();
        switch (timeUnit) {
            case SECONDS:
                span += time * 1000;
                break;
            case MINUTES:
                span += time * (1000 * 60);
                break;
            case HOURS:
                span += time * (1000 * 60 * 60);
                break;
            case DAYS:
                span += time * (1000 * 60 * 60 * 24);
                break;
            default:
                span += time * (1000 * 60);
                break;
        }

        return new TimeSpan(span);
    }

    /**
     * If TimeSpan was cleared - time span will be added to the current time.
     *
     * @param milliseconds
     */
    public void add(long milliseconds) {
        if (date == null)
            date = new Date();

        this.date.setTime(date.getTime() + milliseconds);
    }

    /**
     * If TimeSpan was cleared - time span will be added to the current time.
     *
     * @param time
     * @param timeUnit supported TimeUnit: SECONDS, MINUTES, HOURS, DAYS.
     *                 Otherwise minutes unit will be used as default.
     */
    public void add(int time, TimeUnit timeUnit) {
        if (date == null)
            date = new Date();

        switch (timeUnit) {
            case SECONDS:
                this.date.setTime(date.getTime() + time * 1000);
                break;
            case MINUTES:
                this.date.setTime(date.getTime() + time * (1000 * 60));
                break;
            case HOURS:
                this.date.setTime(date.getTime() + time * (1000 * 60 * 60));
                break;
            case DAYS:
                this.date.setTime(date.getTime() + time * (1000 * 60 * 60 * 24));
                break;
            default:
                this.date.setTime(date.getTime() + time * (1000 * 60));
                break;
        }
    }

    /**
     * Decrease the expire interval
     *
     * @param milliseconds to decrease the expire interval
     */
    public void decrease(long milliseconds) {
        this.date.setTime(date.getTime() - milliseconds);
    }

    /**
     * Clears the expire date. To use this object once more after clearing - you have to set new expire date
     * or 0 (zero) will be returned when you will try to get the time span
     */
    public void clear() {
        date = null;
    }

    /**
     * Milliseconds since January 1, 1970, 00:00:00 GMT of expire date
     *
     * @return milliseconds since January 1, 1970, 00:00:00 GMT of expire date
     */
    public long getMilliseconds() {
        if (date != null)
            return date.getTime();
        else
            return 0;
    }

    /**
     * Get span in specified TimeUnit
     *
     * @param timeUnit supported TimeUnit: SECONDS, MINUTES, HOURS, DAYS.
     *                 Otherwise milliseconds will be returned.
     * @return Time Span in specified unit.
     * For unsupported units milliseconds will be returned.
     * If TimeSpan was cleared - 0 will be returned.
     */
    public long getSpan(TimeUnit timeUnit) {
        if (date == null)
            return 0;

        switch (timeUnit) {
            case SECONDS:
                return (new Date().getTime() - date.getTime()) / 1000;
            case MINUTES:
                return date.getTime() / (1000 * 60);
            case HOURS:
                return date.getTime() / (1000 * 60 * 60);
            case DAYS:
                return date.getTime() / (1000 * 60 * 60 * 24);
            default:
                return date.getTime();
        }
    }

    /**
     * Retrieve expire date
     *
     * @return expire <code>Date</code> object
     */
    public Date getExpireDate() {
        return date;
    }

    /**
     * Set expire date
     *
     * @return set <code>Date</code> object
     */
    public void setExpireDate(Date date) {
        this.date = date;
    }

    /**
     * Check if time span is expired
     *
     * @return <code>true</code> if already expired, otherwise <code>false</code>
     */
    public boolean isExpired() {
        return new Date().after(date);
    }

    /**
     * Get Timestamp in UTC Time format
     *
     * @return number of seconds since 00:00:00 1 January 1970
     */
    public long getTimestamp() {
        if (date == null)
            return 0;

        return date.getTime() / 1000;
    }
}
